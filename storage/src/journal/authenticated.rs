//! Authenticated journal implementation.
//!
//! An authenticated journal maintains a contiguous journal of items alongside a Merkle Mountain
//! Range (MMR). The item at index i in the journal corresponds to the leaf at Location i in the
//! MMR. This structure enables efficient proofs that an item is included in the journal at a
//! specific location.

use crate::{
    journal::{
        contiguous::{fixed, variable, Contiguous, Many, Mutable, Reader},
        Error as JournalError,
    },
    mmr::{
        self, batch, journaled::Mmr, Error as MmrError, Location, Position, Proof, Readable,
        StandardHasher,
    },
    Context, Persistable,
};
use alloc::{sync::Arc, vec::Vec};
use commonware_codec::{CodecFixedShared, CodecShared, Encode, EncodeShared};
use commonware_cryptography::{Digest, Hasher};
use core::num::NonZeroU64;
use futures::{future::try_join_all, try_join, TryFutureExt as _};
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur when interacting with an authenticated journal.
#[derive(Error, Debug)]
pub enum Error {
    #[error("mmr error: {0}")]
    Mmr(#[from] mmr::Error),

    #[error("journal error: {0}")]
    Journal(#[from] super::Error),
}

/// A speculative batch whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<H: Hasher, Item: Send + Sync> {
    // The inner batch of MMR leaf digests.
    inner: batch::UnmerkleizedBatch<H::Digest>,
    // The hasher to use for hashing the items.
    hasher: StandardHasher<H>,
    // The items to append from ancestor batches in the chain.
    parent_items: Vec<Arc<Vec<Item>>>,
    // The items to append from this batch.
    items: Vec<Item>,
}

impl<H: Hasher, Item: Encode + Send + Sync> UnmerkleizedBatch<H, Item> {
    /// Add an item to the batch.
    #[allow(clippy::should_implement_trait)]
    pub fn add(mut self, item: Item) -> Self {
        let encoded = item.encode();
        self.inner = self.inner.add(&self.hasher, &encoded);
        self.items.push(item);
        self
    }

    /// Merkleize the batch, computing the root digest.
    pub fn merkleize(self) -> MerkleizedBatch<H::Digest, Item> {
        let mmr = self.inner.merkleize(&self.hasher);
        let mut items = self.parent_items;
        if !self.items.is_empty() {
            items.push(Arc::new(self.items));
        }
        MerkleizedBatch { inner: mmr, items }
    }
}

/// A speculative batch whose root digest has been computed, in contrast to [`UnmerkleizedBatch`].
///
/// `Clone` is O(chain depth) in Arc clones (no data is deep-copied).
#[derive(Clone, Debug)]
pub struct MerkleizedBatch<D: Digest, Item: Send + Sync> {
    /// The inner batch of MMR leaf digests.
    inner: batch::MerkleizedBatch<D>,
    /// The items to append.
    pub(crate) items: Vec<Arc<Vec<Item>>>,
}

impl<D: Digest, Item: Send + Sync> MerkleizedBatch<D, Item> {
    /// Return the root digest of the authenticated journal after this batch is applied.
    pub fn root(&self) -> D {
        self.inner.root()
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<H: Hasher<Digest = D>>(&self) -> UnmerkleizedBatch<H, Item>
    where
        Item: Encode,
    {
        UnmerkleizedBatch {
            parent_items: self.items.clone(),
            inner: self.inner.new_batch(),
            hasher: StandardHasher::new(),
            items: Vec::new(),
        }
    }

    /// Consume this batch, collecting the changes from its ancestors and itself into a
    /// [`Changeset`] which can be applied to the journal.
    pub fn finalize(self) -> Changeset<D, Item> {
        Changeset {
            changeset: self.inner.finalize(),
            items: self.items,
        }
    }

    /// Like [`Self::finalize`], but produces a [`Changeset`] relative to `current_base`,
    /// skipping `items_to_skip` items from the front of the chain (already committed).
    ///
    /// Use this when an ancestor batch in the chain has already been committed, advancing
    /// the journal's size past the original fork point. For example, given a chain
    /// `journal -> A -> B`, after committing A: call `B.finalize_from(journal.mmr.size(),
    /// A_item_count)` to produce a changeset containing only B's items and MMR delta.
    ///
    /// # Panics
    ///
    /// Panics if `items_to_skip` exceeds the total number of items in the chain.
    pub fn finalize_from(self, current_base: Position, items_to_skip: u64) -> Changeset<D, Item>
    where
        Item: Clone,
    {
        let mut remaining = items_to_skip as usize;
        let mut items = Vec::with_capacity(self.items.len());
        for seg in self.items {
            if remaining >= seg.len() {
                remaining -= seg.len();
                continue;
            }
            if remaining > 0 {
                items.push(Arc::new(seg[remaining..].to_vec()));
                remaining = 0;
            } else {
                items.push(seg);
            }
        }
        assert_eq!(remaining, 0, "items_to_skip exceeds total items in chain");
        Changeset {
            changeset: self.inner.finalize_from(current_base),
            items,
        }
    }
}

impl<D: Digest, Item: Send + Sync> Readable for MerkleizedBatch<D, Item> {
    type Family = mmr::Family;
    type Digest = D;
    type Error = mmr::Error;

    fn size(&self) -> Position {
        self.inner.size()
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        self.inner.get_node(pos)
    }

    fn root(&self) -> D {
        self.inner.root()
    }

    fn pruning_boundary(&self) -> Location {
        self.inner.pruning_boundary()
    }

    fn proof(
        &self,
        hasher: &impl crate::merkle::hasher::Hasher<mmr::Family, Digest = D>,
        loc: Location,
    ) -> Result<Proof<D>, mmr::Error> {
        self.inner.proof(hasher, loc)
    }

    fn range_proof(
        &self,
        hasher: &impl crate::merkle::hasher::Hasher<mmr::Family, Digest = D>,
        range: core::ops::Range<Location>,
    ) -> Result<Proof<D>, mmr::Error> {
        self.inner.range_proof(hasher, range)
    }
}

/// An owned changeset that can be applied to the journal.
pub struct Changeset<D: Digest, Item> {
    // The inner MMR changeset.
    changeset: batch::Changeset<D>,
    // The items to append.
    items: Vec<Arc<Vec<Item>>>,
}

/// An append-only data structure that maintains a sequential journal of items alongside a Merkle
/// Mountain Range (MMR). The item at index i in the journal corresponds to the leaf at Location i
/// in the MMR. This structure enables efficient proofs that an item is included in the journal at a
/// specific location.
pub struct Journal<E, C, H>
where
    E: Context,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// MMR where each leaf is an item digest.
    /// Invariant: leaf i corresponds to item i in the journal.
    pub(crate) mmr: Mmr<E, H::Digest>,

    /// Journal of items.
    /// Invariant: item i corresponds to leaf i in the MMR.
    pub(crate) journal: C,

    pub(crate) hasher: StandardHasher<H>,
}

impl<E, C, H> Journal<E, C, H>
where
    E: Context,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// Returns the Location of the next item appended to the journal.
    pub async fn size(&self) -> Location {
        Location::new(self.journal.size().await)
    }

    /// Return the root of the MMR.
    pub fn root(&self) -> H::Digest {
        self.mmr.root()
    }

    /// Create a speculative batch atop this journal.
    pub fn new_batch(&self) -> UnmerkleizedBatch<H, C::Item>
    where
        C::Item: Encode,
    {
        self.to_merkleized_batch().new_batch()
    }

    /// Create an owned [`MerkleizedBatch`] representing the current committed state.
    ///
    /// The batch has no items (the committed items are on disk, not in memory).
    /// This is the starting point for building owned batch chains.
    pub(crate) fn to_merkleized_batch(&self) -> MerkleizedBatch<H::Digest, C::Item> {
        MerkleizedBatch {
            inner: self.mmr.to_batch(),
            items: Vec::new(),
        }
    }
}

impl<E, C, H> Journal<E, C, H>
where
    E: Context,
    C: Contiguous<Item: EncodeShared> + Persistable<Error = JournalError>,
    H: Hasher,
{
    /// Durably persist the journal. This is faster than `sync()` but does not persist the MMR,
    /// meaning recovery will be required on startup if we crash before `sync()`.
    pub async fn commit(&self) -> Result<(), Error> {
        self.journal.commit().await.map_err(Error::Journal)
    }
}

impl<E, C, H> Journal<E, C, H>
where
    E: Context,
    C: Mutable<Item: EncodeShared>,
    H: Hasher,
{
    /// Create a new [Journal] from the given components after aligning the MMR with the journal.
    pub async fn from_components(
        mut mmr: Mmr<E, H::Digest>,
        journal: C,
        hasher: StandardHasher<H>,
        apply_batch_size: u64,
    ) -> Result<Self, Error> {
        Self::align(&mut mmr, &journal, &hasher, apply_batch_size).await?;

        // Sync the MMR to disk to avoid having to repeat any recovery that may have been performed
        // on next startup.
        mmr.sync().await?;

        Ok(Self {
            mmr,
            journal,
            hasher,
        })
    }

    /// Align `mmr` to be consistent with `journal`. Any items in `mmr` that aren't in `journal` are
    /// popped, and any items in `journal` that aren't in `mmr` are added to `mmr`. Items are added
    /// to `mmr` in batches of size `apply_batch_size` to avoid memory bloat.
    async fn align(
        mmr: &mut Mmr<E, H::Digest>,
        journal: &C,
        hasher: &StandardHasher<H>,
        apply_batch_size: u64,
    ) -> Result<(), Error> {
        // Rewind MMR elements that are ahead of the journal.
        // Note mmr_size is the size of the MMR in leaves, not positions.
        let journal_size = journal.size().await;
        let mut mmr_size = mmr.leaves();
        if mmr_size > journal_size {
            let rewind_count = mmr_size - journal_size;
            warn!(
                journal_size,
                ?rewind_count,
                "rewinding MMR to match journal"
            );
            mmr.rewind(*rewind_count as usize, hasher).await?;
            mmr_size = Location::new(journal_size);
        }

        // If the MMR is behind, replay journal items to catch up.
        if mmr_size < journal_size {
            let replay_count = journal_size - *mmr_size;
            warn!(
                ?journal_size,
                replay_count, "MMR lags behind journal, replaying journal to catch up"
            );

            let reader = journal.reader().await;
            while mmr_size < journal_size {
                let changeset = {
                    let mut batch = mmr.new_batch();
                    let mut count = 0u64;
                    while count < apply_batch_size && mmr_size < journal_size {
                        let op = reader.read(*mmr_size).await?;
                        batch = batch.add(hasher, &op.encode());
                        mmr_size += 1;
                        count += 1;
                    }
                    batch.merkleize(hasher).finalize()
                };
                mmr.apply(changeset)?;
            }
            return Ok(());
        }

        // At this point the MMR and journal should be consistent.
        assert_eq!(journal.size().await, *mmr.leaves());

        Ok(())
    }

    /// Append an item to the journal and update the MMR.
    pub async fn append(&mut self, item: &C::Item) -> Result<Location, Error> {
        let encoded_item = item.encode();

        // Append item to the journal, then update the MMR state.
        let loc = self.journal.append(item).await?;
        let changeset = self
            .mmr
            .new_batch()
            .add(&self.hasher, &encoded_item)
            .merkleize(&self.hasher)
            .finalize();
        self.mmr.apply(changeset)?;

        Ok(Location::new(loc))
    }

    /// Apply a changeset to the journal.
    ///
    /// A changeset is only valid if the journal has not been modified since the
    /// batch that produced it was created. Multiple batches can be forked from the
    /// same parent for speculative execution, but only one may be applied. Applying
    /// a stale changeset returns an error.
    pub async fn apply_batch(&mut self, batch: Changeset<H::Digest, C::Item>) -> Result<(), Error> {
        let actual = self.mmr.size();
        if batch.changeset.base_size != actual {
            return Err(MmrError::StaleChangeset {
                expected: batch.changeset.base_size,
                actual,
            }
            .into());
        }

        self.journal
            .append_many(Many::nested(&batch.items))
            .await?;
        self.mmr.apply(batch.changeset)?;
        assert_eq!(*self.mmr.leaves(), self.journal.size().await);
        Ok(())
    }

    /// Prune both the MMR and journal to the given location.
    ///
    /// # Returns
    /// The new pruning boundary, which may be less than the requested `prune_loc`.
    pub async fn prune(&mut self, prune_loc: Location) -> Result<Location, Error> {
        if self.mmr.size() == 0 {
            // DB is empty, nothing to prune.
            return Ok(Location::new(self.reader().await.bounds().start));
        }

        // Sync the MMR before pruning the journal, otherwise the MMR's last element could end up
        // behind the journal's first element after a crash, and there would be no way to replay
        // the items between the MMR's last element and the journal's first element.
        self.mmr.sync().await?;

        // Prune the journal and check if anything was actually pruned
        if !self.journal.prune(*prune_loc).await? {
            return Ok(Location::new(self.reader().await.bounds().start));
        }

        let bounds = self.reader().await.bounds();
        debug!(size = ?bounds.end, ?prune_loc, boundary = ?bounds.start, "pruned inactive ops");

        // Prune MMR to match the journal's actual boundary
        self.mmr.prune(Location::from(bounds.start)).await?;

        Ok(Location::new(bounds.start))
    }
}

impl<E, C, H> Journal<E, C, H>
where
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
    /// - Returns [Error::Mmr] with [MmrError::LocationOverflow] if `start_loc` >
    ///   [crate::merkle::Family::MAX_LEAVES].
    /// - Returns [Error::Mmr] with [MmrError::RangeOutOfBounds] if `start_loc` >= current
    ///   item count.
    /// - Returns [Error::Journal] with [crate::journal::Error::ItemPruned] if `start_loc` has been
    ///   pruned.
    pub async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<C::Item>), Error> {
        self.historical_proof(self.size().await, start_loc, max_ops)
            .await
    }

    /// Generate a historical proof with respect to the state of the MMR when it had
    /// `historical_leaves` leaves.
    ///
    /// Returns a proof and the items corresponding to the leaves in the range `start_loc..end_loc`,
    /// where `end_loc` is the minimum of `historical_leaves` and `start_loc + max_ops`.
    ///
    /// # Errors
    ///
    /// - Returns [Error::Mmr] with [MmrError::RangeOutOfBounds] if `start_loc` >=
    ///   `historical_leaves` or `historical_leaves` > number of items in the journal.
    /// - Returns [Error::Journal] with [crate::journal::Error::ItemPruned] if `start_loc` has been
    ///   pruned.
    pub async fn historical_proof(
        &self,
        historical_leaves: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<C::Item>), Error> {
        // Acquire a reader guard to prevent pruning from advancing while we read.
        let reader = self.journal.reader().await;
        let bounds = reader.bounds();

        if *historical_leaves > bounds.end {
            return Err(MmrError::RangeOutOfBounds(Location::new(bounds.end)).into());
        }
        if start_loc >= historical_leaves {
            return Err(MmrError::RangeOutOfBounds(start_loc).into());
        }

        let end_loc = std::cmp::min(historical_leaves, start_loc.saturating_add(max_ops.get()));

        let hasher = self.hasher.clone();
        let proof = self
            .mmr
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

impl<E, C, H> Journal<E, C, H>
where
    E: Context,
    C: Contiguous<Item: EncodeShared> + Persistable<Error = JournalError>,
    H: Hasher,
{
    /// Destroy the authenticated journal, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(
            self.journal.destroy().map_err(Error::Journal),
            self.mmr.destroy().map_err(Error::Mmr),
        )?;

        Ok(())
    }

    /// Durably persist the journal, ensuring no recovery is required on startup.
    pub async fn sync(&self) -> Result<(), Error> {
        try_join!(
            self.journal.sync().map_err(Error::Journal),
            self.mmr.sync().map_err(Error::Mmr)
        )?;

        Ok(())
    }
}

/// The number of items to apply to the MMR in a single batch.
const APPLY_BATCH_SIZE: u64 = 1 << 16;

/// Generate a `new()` constructor for an authenticated journal backed by a specific contiguous
/// journal type.
macro_rules! impl_journal_new {
    ($journal_mod:ident, $cfg_ty:ty, $codec_bound:path) => {
        impl<E, O, H> Journal<E, $journal_mod::Journal<E, O>, H>
        where
            E: Context,
            O: $codec_bound,
            H: Hasher,
        {
            /// Create a new authenticated [Journal].
            ///
            /// The inner journal will be rewound to the last item matching `rewind_predicate`,
            /// and the MMR will be aligned to match.
            pub async fn new(
                context: E,
                mmr_cfg: crate::mmr::journaled::Config,
                journal_cfg: $cfg_ty,
                rewind_predicate: fn(&O) -> bool,
            ) -> Result<Self, Error> {
                let mut journal =
                    $journal_mod::Journal::init(context.with_label("journal"), journal_cfg).await?;
                journal.rewind_to(rewind_predicate).await?;

                let hasher = StandardHasher::<H>::new();
                let mut mmr = Mmr::init(context.with_label("mmr"), &hasher, mmr_cfg).await?;
                Self::align(&mut mmr, &journal, &hasher, APPLY_BATCH_SIZE).await?;

                journal.sync().await?;
                mmr.sync().await?;

                Ok(Self {
                    mmr,
                    journal,
                    hasher,
                })
            }
        }
    };
}

impl_journal_new!(fixed, fixed::Config, CodecFixedShared);
impl_journal_new!(variable, variable::Config<O::Cfg>, CodecShared);

impl<E, C, H> Contiguous for Journal<E, C, H>
where
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

impl<E, C, H> Mutable for Journal<E, C, H>
where
    E: Context,
    C: Mutable<Item: EncodeShared>,
    H: Hasher,
{
    async fn append(&mut self, item: &Self::Item) -> Result<u64, JournalError> {
        let res = self.append(item).await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Mmr(inner) => JournalError::Mmr(anyhow::Error::from(inner)),
        })?;

        Ok(*res)
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, JournalError> {
        self.journal.prune(min_position).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), JournalError> {
        self.journal.rewind(size).await?;

        let leaves = *self.mmr.leaves();
        if leaves > size {
            self.mmr
                .rewind((leaves - size) as usize, &self.hasher)
                .await
                .map_err(|error| JournalError::Mmr(anyhow::Error::from(error)))?;
        }

        Ok(())
    }
}

/// A [Mutable] journal that can serve as the inner journal of an authenticated [Journal].
pub trait Inner<E: Context>: Mutable + Persistable<Error = JournalError> {
    /// The configuration needed to initialize this journal.
    type Config: Clone + Send;

    /// Initialize an authenticated [Journal] backed by this journal type.
    fn init<H: Hasher>(
        context: E,
        mmr_cfg: mmr::journaled::Config,
        journal_cfg: Self::Config,
        rewind_predicate: fn(&Self::Item) -> bool,
    ) -> impl core::future::Future<Output = Result<Journal<E, Self, H>, Error>> + Send
    where
        Self: Sized,
        Self::Item: EncodeShared;
}

impl<E, C, H> Persistable for Journal<E, C, H>
where
    E: Context,
    C: Contiguous<Item: EncodeShared> + Persistable<Error = JournalError>,
    H: Hasher,
{
    type Error = JournalError;

    async fn commit(&self) -> Result<(), JournalError> {
        self.commit().await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Mmr(inner) => JournalError::Mmr(anyhow::Error::from(inner)),
        })
    }

    async fn sync(&self) -> Result<(), JournalError> {
        self.sync().await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Mmr(inner) => JournalError::Mmr(anyhow::Error::from(inner)),
        })
    }

    async fn destroy(self) -> Result<(), JournalError> {
        self.destroy().await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Mmr(inner) => JournalError::Mmr(anyhow::Error::from(inner)),
        })
    }
}

#[cfg(test)]
impl<E, C, H> Journal<E, C, H>
where
    E: Context,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// Test helper: Read the item at the given location.
    pub(crate) async fn read(&self, loc: Location) -> Result<C::Item, Error> {
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
        mmr::{
            journaled::{Config as MmrConfig, Mmr},
            Location,
        },
        qmdb::{
            any::unordered::{fixed::Operation, Update},
            operation::Committable,
        },
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{sha256, sha256::Digest, Sha256};
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

    /// Create MMR configuration for tests.
    fn mmr_config(suffix: &str, pooler: &impl BufferPooler) -> MmrConfig {
        MmrConfig {
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

    type AuthenticatedJournal = Journal<
        deterministic::Context,
        ContiguousJournal<deterministic::Context, Operation<Digest, Digest>>,
        Sha256,
    >;

    /// Create a new empty authenticated journal.
    async fn create_empty_journal(context: Context, suffix: &str) -> AuthenticatedJournal {
        let mmr_cfg = mmr_config(suffix, &context);
        let journal_cfg = journal_config(suffix, &context);
        AuthenticatedJournal::new(
            context,
            mmr_cfg,
            journal_cfg,
            |op: &Operation<Digest, Digest>| op.is_commit(),
        )
        .await
        .unwrap()
    }

    /// Create a test operation with predictable values based on index.
    fn create_operation(index: u8) -> Operation<Digest, Digest> {
        Operation::Update(Update(
            Sha256::fill(index),
            Sha256::fill(index.wrapping_add(1)),
        ))
    }

    /// Create an authenticated journal with N committed operations.
    ///
    /// Operations are added and then synced to ensure they are committed.
    async fn create_journal_with_ops(
        context: Context,
        suffix: &str,
        count: usize,
    ) -> AuthenticatedJournal {
        let mut journal = create_empty_journal(context, suffix).await;

        for i in 0..count {
            let op = create_operation(i as u8);
            let loc = journal.append(&op).await.unwrap();
            assert_eq!(loc, Location::new(i as u64));
        }

        journal.sync().await.unwrap();
        journal
    }

    /// Create separate MMR and journal components for testing alignment.
    ///
    /// These components are created independently and can be manipulated separately to test
    /// scenarios where the MMR and journal are out of sync (e.g., one ahead of the other).
    async fn create_components(
        context: Context,
        suffix: &str,
    ) -> (
        Mmr<deterministic::Context, sha256::Digest>,
        ContiguousJournal<deterministic::Context, Operation<Digest, Digest>>,
        StandardHasher<Sha256>,
    ) {
        let hasher = StandardHasher::new();
        let mmr = Mmr::init(
            context.with_label("mmr"),
            &hasher,
            mmr_config(suffix, &context),
        )
        .await
        .unwrap();
        let journal = ContiguousJournal::init(
            context.with_label("journal"),
            journal_config(suffix, &context),
        )
        .await
        .unwrap();
        (mmr, journal, hasher)
    }

    /// Verify that a proof correctly proves the given operations are included in the MMR.
    fn verify_proof(
        proof: &mmr::Proof<<Sha256 as commonware_cryptography::Hasher>::Digest>,
        operations: &[Operation<Digest, Digest>],
        start_loc: Location,
        root: &<Sha256 as commonware_cryptography::Hasher>::Digest,
        hasher: &StandardHasher<Sha256>,
    ) -> bool {
        let encoded_ops: Vec<_> = operations.iter().map(|op| op.encode()).collect();
        proof.verify_range_inclusion(hasher, &encoded_ops, start_loc, root)
    }

    /// Verify that new() creates an empty authenticated journal.
    #[test_traced("INFO")]
    fn test_new_creates_empty_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_empty_journal(context, "new-empty").await;

            let bounds = journal.reader().await.bounds();
            assert_eq!(bounds.end, 0);
            assert_eq!(bounds.start, 0);
            assert!(bounds.is_empty());
        });
    }

    /// Verify that align() correctly handles empty MMR and journal components.
    #[test_traced("INFO")]
    fn test_align_with_empty_mmr_and_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut mmr, journal, hasher) = create_components(context, "align-empty").await;

            AuthenticatedJournal::align(&mut mmr, &journal, &hasher, APPLY_BATCH_SIZE)
                .await
                .unwrap();

            assert_eq!(mmr.leaves(), Location::new(0));
            assert_eq!(journal.size().await, 0);
        });
    }

    /// Verify that align() pops MMR elements when MMR is ahead of the journal.
    #[test_traced("WARN")]
    fn test_align_when_mmr_ahead() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut mmr, journal, hasher) = create_components(context, "mmr-ahead").await;

            // Add 20 operations to both MMR and journal
            {
                let changeset = {
                    let mut batch = mmr.new_batch();
                    for i in 0..20 {
                        let op = create_operation(i as u8);
                        let encoded = op.encode();
                        batch = batch.add(&hasher, &encoded);
                        journal.append(&op).await.unwrap();
                    }
                    batch.merkleize(&hasher).finalize()
                };
                mmr.apply(changeset).unwrap();
            }

            // Add commit operation to journal only (making journal ahead)
            let commit_op = Operation::CommitFloor(None, Location::new(0));
            journal.append(&commit_op).await.unwrap();
            journal.sync().await.unwrap();

            // MMR has 20 leaves, journal has 21 operations (20 ops + 1 commit)
            AuthenticatedJournal::align(&mut mmr, &journal, &hasher, APPLY_BATCH_SIZE)
                .await
                .unwrap();

            // MMR should have been aligned to match journal
            assert_eq!(mmr.leaves(), Location::new(21));
            assert_eq!(journal.size().await, 21);
        });
    }

    /// Verify that align() replays journal operations when journal is ahead of MMR.
    #[test_traced("WARN")]
    fn test_align_when_journal_ahead() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut mmr, journal, hasher) = create_components(context, "journal-ahead").await;

            // Add 20 operations to journal only
            for i in 0..20 {
                let op = create_operation(i as u8);
                journal.append(&op).await.unwrap();
            }

            // Add commit
            let commit_op = Operation::CommitFloor(None, Location::new(0));
            journal.append(&commit_op).await.unwrap();
            journal.sync().await.unwrap();

            // Journal has 21 operations, MMR has 0 leaves
            AuthenticatedJournal::align(&mut mmr, &journal, &hasher, APPLY_BATCH_SIZE)
                .await
                .unwrap();

            // MMR should have been replayed to match journal
            assert_eq!(mmr.leaves(), Location::new(21));
            assert_eq!(journal.size().await, 21);
        });
    }

    /// Verify that align() discards uncommitted operations.
    #[test_traced("INFO")]
    fn test_align_with_mismatched_committed_ops() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_empty_journal(context.with_label("first"), "mismatched").await;

            // Add 20 uncommitted operations
            for i in 0..20 {
                let loc = journal.append(&create_operation(i as u8)).await.unwrap();
                assert_eq!(loc, Location::new(i as u64));
            }

            // Don't sync - these are uncommitted
            // After alignment, they should be discarded
            let size_before = journal.size().await;
            assert_eq!(size_before, 20);

            // Drop and recreate to simulate restart (which calls align internally)
            journal.sync().await.unwrap();
            drop(journal);
            let journal = create_empty_journal(context.with_label("second"), "mismatched").await;

            // Uncommitted operations should be gone
            assert_eq!(journal.size().await, 0);
        });
    }

    #[test_traced("INFO")]
    fn test_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
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
                    journal.append(&create_operation(i)).await.unwrap();
                }
                journal
                    .append(&Operation::CommitFloor(None, Location::new(0)))
                    .await
                    .unwrap();
                for i in 4..7 {
                    journal.append(&create_operation(i)).await.unwrap();
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
                journal.append(&create_operation(0)).await.unwrap();
                journal
                    .append(&Operation::CommitFloor(None, Location::new(0)))
                    .await
                    .unwrap(); // pos 1
                journal.append(&create_operation(2)).await.unwrap();
                journal
                    .append(&Operation::CommitFloor(None, Location::new(1)))
                    .await
                    .unwrap(); // pos 3
                journal.append(&create_operation(4)).await.unwrap();

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
                    journal.append(&create_operation(i)).await.unwrap();
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
                    journal.append(&create_operation(i)).await.unwrap();
                }
                journal
                    .append(&Operation::CommitFloor(None, Location::new(0)))
                    .await
                    .unwrap(); // pos 10
                for i in 11..15 {
                    journal.append(&create_operation(i)).await.unwrap();
                }
                journal.sync().await.unwrap();

                // Prune up to position 8 (this will prune section 0, items 0-6, keeping 7+)
                journal.prune(8).await.unwrap();
                assert_eq!(journal.reader().await.bounds().start, 7);

                // Add more uncommitted operations
                for i in 15..20 {
                    journal.append(&create_operation(i)).await.unwrap();
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
                    journal.append(&create_operation(i)).await.unwrap();
                }
                journal
                    .append(&Operation::CommitFloor(None, Location::new(0)))
                    .await
                    .unwrap(); // pos 5
                for i in 6..10 {
                    journal.append(&create_operation(i)).await.unwrap();
                }
                journal.sync().await.unwrap();

                // Prune up to position 8 (this prunes section 0, including the commit at pos 5)
                // Pruning boundary will be at position 7 (start of section 1)
                journal.prune(8).await.unwrap();
                assert_eq!(journal.reader().await.bounds().start, 7);

                // Add uncommitted operations with no commits (in section 1: 7-13)
                for i in 10..14 {
                    journal.append(&create_operation(i)).await.unwrap();
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
                    .rewind_to(|op: &Operation<Digest, Digest>| op.is_commit())
                    .await
                    .unwrap();
                assert_eq!(final_size, 0);
                assert_eq!(journal.size().await, 0);
            }

            // Test 7: Position based authenticated journal rewind.
            {
                let mmr_cfg = mmr_config("rewind", &context);
                let journal_cfg = journal_config("rewind", &context);
                let mut journal =
                    AuthenticatedJournal::new(context, mmr_cfg, journal_cfg, |op| op.is_commit())
                        .await
                        .unwrap();

                // Add operations with a commit at position 5 (in section 0: 0-6)
                for i in 0..5 {
                    journal.append(&create_operation(i)).await.unwrap();
                }
                journal
                    .append(&Operation::CommitFloor(None, Location::new(0)))
                    .await
                    .unwrap(); // pos 5
                for i in 6..10 {
                    journal.append(&create_operation(i)).await.unwrap();
                }
                assert_eq!(journal.size().await, 10);

                journal.rewind(2).await.unwrap();
                assert_eq!(journal.size().await, 2);
                assert_eq!(journal.mmr.leaves(), 2);
                assert_eq!(journal.mmr.size(), 3);
                let bounds = journal.reader().await.bounds();
                assert_eq!(bounds.start, 0);
                assert!(!bounds.is_empty());

                assert!(matches!(
                    journal.rewind(3).await,
                    Err(JournalError::InvalidRewind(_))
                ));

                journal.rewind(0).await.unwrap();
                assert_eq!(journal.size().await, 0);
                assert_eq!(journal.mmr.leaves(), 0);
                assert_eq!(journal.mmr.size(), 0);
                let bounds = journal.reader().await.bounds();
                assert_eq!(bounds.start, 0);
                assert!(bounds.is_empty());

                // Test rewinding after pruning.
                for i in 0..255 {
                    journal.append(&create_operation(i)).await.unwrap();
                }
                journal.prune(Location::new(100)).await.unwrap();
                assert_eq!(journal.reader().await.bounds().start, 98);
                let res = journal.rewind(97).await;
                assert!(matches!(res, Err(JournalError::InvalidRewind(97))));
                journal.rewind(98).await.unwrap();
                let bounds = journal.reader().await.bounds();
                assert_eq!(bounds.end, 98);
                assert_eq!(journal.mmr.leaves(), 98);
                assert_eq!(bounds.start, 98);
                assert!(bounds.is_empty());
            }
        });
    }

    /// Verify that append() increments the operation count, returns correct locations, and
    /// operations can be read back correctly.
    #[test_traced("INFO")]
    fn test_apply_op_and_read_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_empty_journal(context, "apply_op").await;

            assert_eq!(journal.size().await, 0);

            // Add 50 operations
            let expected_ops: Vec<_> = (0..50).map(|i| create_operation(i as u8)).collect();
            for (i, op) in expected_ops.iter().enumerate() {
                let loc = journal.append(op).await.unwrap();
                assert_eq!(loc, Location::new(i as u64));
                assert_eq!(journal.size().await, (i + 1) as u64);
            }

            assert_eq!(journal.size().await, 50);

            // Verify all operations can be read back correctly
            journal.sync().await.unwrap();
            for (i, expected_op) in expected_ops.iter().enumerate() {
                let read_op = journal.read(Location::new(i as u64)).await.unwrap();
                assert_eq!(read_op, *expected_op);
            }
        });
    }

    /// Verify that read() returns correct operations at various positions.
    #[test_traced("INFO")]
    fn test_read_operations_at_various_positions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "read", 50).await;

            // Verify reading first operation
            let first_op = journal.read(Location::new(0)).await.unwrap();
            assert_eq!(first_op, create_operation(0));

            // Verify reading middle operation
            let middle_op = journal.read(Location::new(25)).await.unwrap();
            assert_eq!(middle_op, create_operation(25));

            // Verify reading last operation
            let last_op = journal.read(Location::new(49)).await.unwrap();
            assert_eq!(last_op, create_operation(49));

            // Verify all operations match expected values
            for i in 0..50 {
                let op = journal.read(Location::new(i)).await.unwrap();
                assert_eq!(op, create_operation(i as u8));
            }
        });
    }

    /// Verify that read() returns an error for pruned operations.
    #[test_traced("INFO")]
    fn test_read_pruned_operation_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "read_pruned", 100).await;

            // Add commit and prune
            journal
                .append(&Operation::CommitFloor(None, Location::new(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();
            let pruned_boundary = journal.prune(Location::new(50)).await.unwrap();

            // Try to read an operation before the pruned boundary
            let read_loc = Location::new(0);
            if read_loc < pruned_boundary {
                let result = journal.read(read_loc).await;
                assert!(matches!(
                    result,
                    Err(Error::Journal(crate::journal::Error::ItemPruned(_)))
                ));
            }
        });
    }

    /// Verify that read() returns an error for out-of-range locations.
    #[test_traced("INFO")]
    fn test_read_out_of_range_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "read_oob", 3).await;

            // Try to read beyond the end
            let result = journal.read(Location::new(10)).await;
            assert!(matches!(
                result,
                Err(Error::Journal(crate::journal::Error::ItemOutOfRange(_)))
            ));
        });
    }

    /// Verify that we can read all operations back correctly.
    #[test_traced("INFO")]
    fn test_read_all_operations_back_correctly() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "read_all", 50).await;

            assert_eq!(journal.size().await, 50);

            // Verify all operations can be read back and match expected values
            for i in 0..50 {
                let op = journal.read(Location::new(i)).await.unwrap();
                assert_eq!(op, create_operation(i as u8));
            }
        });
    }

    /// Verify that sync() persists operations.
    #[test_traced("INFO")]
    fn test_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal =
                create_empty_journal(context.with_label("first"), "close_pending").await;

            // Add 20 operations
            let expected_ops: Vec<_> = (0..20).map(|i| create_operation(i as u8)).collect();
            for (i, op) in expected_ops.iter().enumerate() {
                let loc = journal.append(op).await.unwrap();
                assert_eq!(loc, Location::new(i as u64),);
            }

            // Add commit operation to commit the operations
            let commit_loc = journal
                .append(&Operation::CommitFloor(None, Location::new(0)))
                .await
                .unwrap();
            assert_eq!(
                commit_loc,
                Location::new(20),
                "commit should be at location 20"
            );
            journal.sync().await.unwrap();

            // Reopen and verify the operations persisted
            drop(journal);
            let journal = create_empty_journal(context.with_label("second"), "close_pending").await;
            assert_eq!(journal.size().await, 21);

            // Verify all operations can be read back
            for (i, expected_op) in expected_ops.iter().enumerate() {
                let read_op = journal.read(Location::new(i as u64)).await.unwrap();
                assert_eq!(read_op, *expected_op);
            }
        });
    }

    /// Verify that pruning an empty journal returns the boundary.
    #[test_traced("INFO")]
    fn test_prune_empty_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_empty_journal(context, "prune_empty").await;

            let boundary = journal.prune(Location::new(0)).await.unwrap();

            assert_eq!(boundary, Location::new(0));
        });
    }

    /// Verify that pruning to a specific location works correctly.
    #[test_traced("INFO")]
    fn test_prune_to_location() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "prune_to", 100).await;

            // Add commit at position 50
            journal
                .append(&Operation::CommitFloor(None, Location::new(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let boundary = journal.prune(Location::new(50)).await.unwrap();

            // Boundary should be <= requested location (may align to section boundary)
            assert!(boundary <= Location::new(50));
        });
    }

    /// Verify that prune() returns the actual boundary (which may differ from requested).
    #[test_traced("INFO")]
    fn test_prune_returns_actual_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "prune_boundary", 100).await;

            journal
                .append(&Operation::CommitFloor(None, Location::new(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let requested = Location::new(50);
            let actual = journal.prune(requested).await.unwrap();

            // Actual boundary should match bounds.start
            let bounds = journal.reader().await.bounds();
            assert!(!bounds.is_empty());
            assert_eq!(actual, bounds.start);

            // Actual may be <= requested due to section alignment
            assert!(actual <= requested);
        });
    }

    /// Verify that pruning doesn't change the operation count.
    #[test_traced("INFO")]
    fn test_prune_preserves_operation_count() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "prune_count", 100).await;

            journal
                .append(&Operation::CommitFloor(None, Location::new(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let count_before = journal.size().await;
            journal.prune(Location::new(50)).await.unwrap();
            let count_after = journal.size().await;

            assert_eq!(count_before, count_after);
        });
    }

    /// Verify bounds() for empty journal, no pruning, and after pruning.
    #[test_traced("INFO")]
    fn test_bounds_empty_and_pruned() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test empty journal
            let journal = create_empty_journal(context.with_label("empty"), "oldest").await;
            assert!(journal.reader().await.bounds().is_empty());
            journal.destroy().await.unwrap();

            // Test no pruning
            let journal =
                create_journal_with_ops(context.with_label("no_prune"), "oldest", 100).await;
            let bounds = journal.reader().await.bounds();
            assert!(!bounds.is_empty());
            assert_eq!(bounds.start, 0);
            journal.destroy().await.unwrap();

            // Test after pruning
            let mut journal =
                create_journal_with_ops(context.with_label("pruned"), "oldest", 100).await;
            journal
                .append(&Operation::CommitFloor(None, Location::new(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let pruned_boundary = journal.prune(Location::new(50)).await.unwrap();

            // Should match the pruned boundary (may be <= 50 due to section alignment)
            let bounds = journal.reader().await.bounds();
            assert!(!bounds.is_empty());
            assert_eq!(bounds.start, pruned_boundary);
            // Should be <= requested location (50)
            assert!(pruned_boundary <= 50);
            journal.destroy().await.unwrap();
        });
    }

    /// Verify bounds().start for empty journal, no pruning, and after pruning.
    #[test_traced("INFO")]
    fn test_bounds_start_after_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test empty journal
            let journal = create_empty_journal(context.with_label("empty"), "boundary").await;
            assert_eq!(journal.reader().await.bounds().start, 0);

            // Test no pruning
            let journal =
                create_journal_with_ops(context.with_label("no_prune"), "boundary", 100).await;
            assert_eq!(journal.reader().await.bounds().start, 0);

            // Test after pruning
            let mut journal =
                create_journal_with_ops(context.with_label("pruned"), "boundary", 100).await;
            journal
                .append(&Operation::CommitFloor(None, Location::new(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let pruned_boundary = journal.prune(Location::new(50)).await.unwrap();

            assert_eq!(journal.reader().await.bounds().start, pruned_boundary);
        });
    }

    /// Verify that MMR prunes to the journal's actual boundary, not the requested location.
    #[test_traced("INFO")]
    fn test_mmr_prunes_to_journal_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "mmr_boundary", 50).await;

            journal
                .append(&Operation::CommitFloor(None, Location::new(25)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let pruned_boundary = journal.prune(Location::new(25)).await.unwrap();

            // Verify MMR and journal remain in sync
            let bounds = journal.reader().await.bounds();
            assert!(!bounds.is_empty());
            assert_eq!(pruned_boundary, bounds.start);

            // Verify boundary is at or before requested (due to section alignment)
            assert!(pruned_boundary <= Location::new(25));

            // Verify operation count is unchanged
            assert_eq!(journal.size().await, 51);
        });
    }

    /// Verify proof() for multiple operations.
    #[test_traced("INFO")]
    fn test_proof_multiple_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_multi", 50).await;

            let (proof, ops) = journal.proof(Location::new(0), NZU64!(50)).await.unwrap();

            assert_eq!(ops.len(), 50);
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(*op, create_operation(i as u8));
            }

            // Verify the proof is valid
            let hasher = StandardHasher::new();
            let root = journal.root();
            assert!(verify_proof(&proof, &ops, Location::new(0), &root, &hasher));
        });
    }

    /// Verify that historical_proof() respects the max_ops limit.
    #[test_traced("INFO")]
    fn test_historical_proof_limited_by_max_ops() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_limit", 50).await;

            let size = journal.size().await;
            let (proof, ops) = journal
                .historical_proof(size, Location::new(0), NZU64!(20))
                .await
                .unwrap();

            // Should return only 20 operations despite 50 being available
            assert_eq!(ops.len(), 20);
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(*op, create_operation(i as u8));
            }

            // Verify the proof is valid
            let hasher = StandardHasher::new();
            let root = journal.root();
            assert!(verify_proof(&proof, &ops, Location::new(0), &root, &hasher));
        });
    }

    /// Verify historical_proof() at the end of the journal.
    #[test_traced("INFO")]
    fn test_historical_proof_at_end_of_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_end", 50).await;

            let size = journal.size().await;
            // Request proof starting near the end
            let (proof, ops) = journal
                .historical_proof(size, Location::new(40), NZU64!(20))
                .await
                .unwrap();

            // Should return only 10 operations (positions 40-49)
            assert_eq!(ops.len(), 10);
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(*op, create_operation((40 + i) as u8));
            }

            // Verify the proof is valid
            let hasher = StandardHasher::new();
            let root = journal.root();
            assert!(verify_proof(
                &proof,
                &ops,
                Location::new(40),
                &root,
                &hasher
            ));
        });
    }

    /// Verify that historical_proof() returns an error for invalid size.
    #[test_traced("INFO")]
    fn test_historical_proof_out_of_range_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_oob", 5).await;

            // Request proof with size > actual journal size
            let result = journal
                .historical_proof(Location::new(10), Location::new(0), NZU64!(1))
                .await;

            assert!(matches!(
                result,
                Err(Error::Mmr(mmr::Error::RangeOutOfBounds(_)))
            ));
        });
    }

    /// Verify that historical_proof() returns an error when start_loc >= size.
    #[test_traced("INFO")]
    fn test_historical_proof_start_too_large_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_start_oob", 5).await;

            let size = journal.size().await;
            // Request proof starting at size (should fail)
            let result = journal.historical_proof(size, size, NZU64!(1)).await;

            assert!(matches!(
                result,
                Err(Error::Mmr(mmr::Error::RangeOutOfBounds(_)))
            ));
        });
    }

    /// Verify historical_proof() for a truly historical state (before more operations added).
    #[test_traced("INFO")]
    fn test_historical_proof_truly_historical() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create journal with initial operations
            let mut journal = create_journal_with_ops(context, "proof_historical", 50).await;

            // Capture root at historical state
            let hasher = StandardHasher::new();
            let historical_root = journal.root();
            let historical_size = journal.size().await;

            // Add more operations after the historical state
            for i in 50..100 {
                journal.append(&create_operation(i as u8)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Generate proof for the historical state
            let (proof, ops) = journal
                .historical_proof(historical_size, Location::new(0), NZU64!(50))
                .await
                .unwrap();

            // Verify operations match expected historical operations
            assert_eq!(ops.len(), 50);
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(*op, create_operation(i as u8));
            }

            // Verify the proof is valid against the historical root
            assert!(verify_proof(
                &proof,
                &ops,
                Location::new(0),
                &historical_root,
                &hasher
            ));
        });
    }

    /// Verify that historical_proof() returns an error when start_loc is pruned.
    #[test_traced("INFO")]
    fn test_historical_proof_pruned_location_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "proof_pruned", 50).await;

            journal
                .append(&Operation::CommitFloor(None, Location::new(25)))
                .await
                .unwrap();
            journal.sync().await.unwrap();
            let pruned_boundary = journal.prune(Location::new(25)).await.unwrap();

            // Try to get proof starting at a location before the pruned boundary
            let size = journal.size().await;
            let start_loc = Location::new(0);
            if start_loc < pruned_boundary {
                let result = journal.historical_proof(size, start_loc, NZU64!(1)).await;

                // Should fail when trying to read pruned operations
                assert!(result.is_err());
            }
        });
    }

    /// Verify replay() with empty journal and multiple operations.
    #[test_traced("INFO")]
    fn test_replay_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test empty journal
            let journal = create_empty_journal(context.with_label("empty"), "replay").await;
            let reader = journal.reader().await;
            let stream = reader.replay(NZUsize!(10), 0).await.unwrap();
            futures::pin_mut!(stream);
            assert!(stream.next().await.is_none());

            // Test replaying all operations
            let journal =
                create_journal_with_ops(context.with_label("with_ops"), "replay", 50).await;
            let reader = journal.reader().await;
            let stream = reader.replay(NZUsize!(100), 0).await.unwrap();
            futures::pin_mut!(stream);

            for i in 0..50 {
                let (pos, op) = stream.next().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(op, create_operation(i as u8));
            }

            assert!(stream.next().await.is_none());
        });
    }

    /// Verify replay() starting from a middle location.
    #[test_traced("INFO")]
    fn test_replay_from_middle() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "replay_middle", 50).await;
            let reader = journal.reader().await;
            let stream = reader.replay(NZUsize!(100), 25).await.unwrap();
            futures::pin_mut!(stream);

            let mut count = 0;
            while let Some(result) = stream.next().await {
                let (pos, op) = result.unwrap();
                assert_eq!(pos, 25 + count);
                assert_eq!(op, create_operation((25 + count) as u8));
                count += 1;
            }

            // Should have replayed positions 25-49 (25 operations)
            assert_eq!(count, 25);
        });
    }

    /// Verify the speculative batch API: fork two batches, verify independent roots, apply one.
    #[test_traced("INFO")]
    fn test_speculative_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "speculative_batch", 10).await;
            let original_root = journal.root();

            // Fork two independent speculative batches.
            let b1 = journal.new_batch();
            let b2 = journal.new_batch();

            // Add different items to each batch.
            let op_a = create_operation(100);
            let op_b = create_operation(200);
            let b1 = b1.add(op_a.clone());
            let b2 = b2.add(op_b);

            // Merkleize and verify independent roots.
            let m1 = b1.merkleize();
            let m2 = b2.merkleize();
            assert_ne!(m1.root(), m2.root());
            assert_ne!(m1.root(), original_root);
            assert_ne!(m2.root(), original_root);

            // Journal root should be unchanged (batches are speculative).
            assert_eq!(journal.root(), original_root);

            // Finalize batch 1 and apply.
            let expected_root = m1.root();
            let finalized = m1.finalize();
            journal.apply_batch(finalized).await.unwrap();

            // Journal should now match the applied batch's root.
            assert_eq!(journal.root(), expected_root);
            assert_eq!(*journal.size().await, 11);
        });
    }

    /// Verify stacking: create batch A, merkleize, create batch B from merkleized A,
    /// merkleize, finalize, and apply. Verify root and items.
    #[test_traced("INFO")]
    fn test_speculative_batch_stacking() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "batch_stacking", 10).await;

            let op_a = create_operation(100);
            let op_b = create_operation(200);

            let (expected_root, finalized) = {
                let batch_a = journal.new_batch();
                let merkleized_a = batch_a.add(op_a.clone()).merkleize();

                let batch_b = merkleized_a.new_batch::<Sha256>();
                let merkleized_b = batch_b.add(op_b.clone()).merkleize();

                let root = merkleized_b.root();
                (root, merkleized_b.finalize())
            };

            journal.apply_batch(finalized).await.unwrap();

            assert_eq!(journal.root(), expected_root);
            assert_eq!(*journal.size().await, 12);

            // Verify both items were appended correctly.
            let read_a = journal.read(Location::new(10)).await.unwrap();
            assert_eq!(read_a, op_a);
            let read_b = journal.read(Location::new(11)).await.unwrap();
            assert_eq!(read_b, op_b);
        });
    }

    #[test_traced("INFO")]
    fn test_stale_batch_sibling() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_empty_journal(context, "stale-sibling").await;
            let op_a = create_operation(1);
            let op_b = create_operation(2);

            // Create two batches from the same base.
            let finalized_a = journal.new_batch().add(op_a.clone()).merkleize().finalize();
            let finalized_b = journal.new_batch().add(op_b).merkleize().finalize();

            // Apply A -- should succeed.
            journal.apply_batch(finalized_a).await.unwrap();
            let expected_root = journal.root();
            let expected_size = journal.size().await;

            // Apply B -- should fail (stale).
            let result = journal.apply_batch(finalized_b).await;
            assert!(
                matches!(
                    result,
                    Err(super::Error::Mmr(mmr::Error::StaleChangeset { .. }))
                ),
                "expected StaleChangeset, got {result:?}"
            );

            // The stale batch must not mutate the journal or desync it from the MMR.
            assert_eq!(journal.root(), expected_root);
            assert_eq!(journal.size().await, expected_size);
            let (_, ops) = journal.proof(Location::new(0), NZU64!(1)).await.unwrap();
            assert_eq!(ops, vec![op_a]);
        });
    }

    #[test_traced("INFO")]
    fn test_stale_batch_chained() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "stale-chained", 5).await;

            // Parent batch, then fork two children.
            let parent = journal.new_batch().add(create_operation(10)).merkleize();
            let child_a = parent
                .new_batch::<Sha256>()
                .add(create_operation(20))
                .merkleize()
                .finalize();
            let child_b = parent
                .new_batch::<Sha256>()
                .add(create_operation(30))
                .merkleize()
                .finalize();
            drop(parent);

            // Apply child_a, then child_b should be stale.
            journal.apply_batch(child_a).await.unwrap();
            let result = journal.apply_batch(child_b).await;
            assert!(
                matches!(
                    result,
                    Err(super::Error::Mmr(mmr::Error::StaleChangeset { .. }))
                ),
                "expected StaleChangeset for sibling, got {result:?}"
            );
        });
    }

    #[test_traced("INFO")]
    fn test_stale_batch_parent_before_child() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_empty_journal(context, "stale-parent-first").await;

            // Create parent, then child.
            let (parent_finalized, child_finalized) = {
                let parent = journal.new_batch().add(create_operation(1)).merkleize();
                let child = parent
                    .new_batch::<Sha256>()
                    .add(create_operation(2))
                    .merkleize()
                    .finalize();
                (parent.finalize(), child)
            };

            // Apply parent first -- child should now be stale.
            journal.apply_batch(parent_finalized).await.unwrap();
            let result = journal.apply_batch(child_finalized).await;
            assert!(
                matches!(
                    result,
                    Err(super::Error::Mmr(mmr::Error::StaleChangeset { .. }))
                ),
                "expected StaleChangeset for child after parent applied, got {result:?}"
            );
        });
    }

    #[test_traced("INFO")]
    fn test_stale_batch_child_before_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_empty_journal(context, "stale-child-first").await;

            // Create parent, then child.
            let (parent_finalized, child_finalized) = {
                let parent = journal.new_batch().add(create_operation(1)).merkleize();
                let child = parent
                    .new_batch::<Sha256>()
                    .add(create_operation(2))
                    .merkleize()
                    .finalize();
                (parent.finalize(), child)
            };

            // Apply child first -- parent should now be stale.
            journal.apply_batch(child_finalized).await.unwrap();
            let result = journal.apply_batch(parent_finalized).await;
            assert!(
                matches!(
                    result,
                    Err(super::Error::Mmr(mmr::Error::StaleChangeset { .. }))
                ),
                "expected StaleChangeset for parent after child applied, got {result:?}"
            );
        });
    }

    /// finalize_from with items_to_skip=0 produces the same changeset as finalize.
    #[test_traced("INFO")]
    fn test_finalize_from_skip_zero() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "ff-skip0", 5).await;

            let batch = journal
                .new_batch()
                .add(create_operation(10))
                .add(create_operation(11));
            let merkleized = batch.merkleize();

            let normal = merkleized.clone().finalize();
            let from = merkleized.finalize_from(journal.mmr.size(), 0);

            // Same root, same items.
            assert_eq!(normal.changeset.root, from.changeset.root);
            assert_eq!(normal.items.len(), from.items.len());
            for (a, b) in normal.items.iter().zip(from.items.iter()) {
                assert_eq!(a.as_ref(), b.as_ref());
            }
        });
    }

    /// finalize_from correctly skips items when an ancestor has been committed.
    #[test_traced("INFO")]
    fn test_finalize_from_skip_ancestor_items() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "ff-skip", 3).await;

            // Parent: 2 items.
            let parent = journal
                .new_batch()
                .add(create_operation(10))
                .add(create_operation(11))
                .merkleize();

            // Child: 3 more items.
            let child = parent
                .new_batch::<Sha256>()
                .add(create_operation(20))
                .add(create_operation(21))
                .add(create_operation(22))
                .merkleize();

            // Commit parent.
            journal.apply_batch(parent.finalize()).await.unwrap();

            // finalize_from on child, skipping the 2 parent items.
            let changeset = child.finalize_from(journal.mmr.size(), 2);

            // Should contain exactly the 3 child items.
            let total_items: usize = changeset.items.iter().map(|s| s.len()).sum();
            assert_eq!(total_items, 3);

            // The changeset should be applicable.
            journal.apply_batch(changeset).await.unwrap();

            // Verify all items are present.
            let (_, ops) = journal.proof(Location::new(3), NZU64!(5)).await.unwrap();
            assert_eq!(ops.len(), 5);
        });
    }

    /// finalize_from skips items that span across segment boundaries.
    #[test_traced("INFO")]
    fn test_finalize_from_cross_segment_skip() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "ff-cross", 2).await;

            // Grandparent: 3 items (segment 1).
            let grandparent = journal
                .new_batch()
                .add(create_operation(3))
                .add(create_operation(4))
                .add(create_operation(5))
                .merkleize();

            // Parent: 2 items (segment 2).
            let parent = grandparent
                .new_batch::<Sha256>()
                .add(create_operation(6))
                .add(create_operation(7))
                .merkleize();

            // Child: 1 item (segment 3).
            let child = parent
                .new_batch::<Sha256>()
                .add(create_operation(8))
                .merkleize();

            // Commit grandparent (3 items).
            journal.apply_batch(grandparent.finalize()).await.unwrap();

            // Commit parent via finalize_from, skipping grandparent's 3 items.
            let changeset = parent.finalize_from(journal.mmr.size(), 3);
            let parent_items: usize = changeset.items.iter().map(|s| s.len()).sum();
            assert_eq!(parent_items, 2);
            journal.apply_batch(changeset).await.unwrap();

            // Commit child via finalize_from, skipping grandparent's 3 + parent's 2 = 5 items.
            let changeset = child.finalize_from(journal.mmr.size(), 5);
            let child_items: usize = changeset.items.iter().map(|s| s.len()).sum();
            assert_eq!(child_items, 1);
            journal.apply_batch(changeset).await.unwrap();

            // All 8 items (2 base + 3 + 2 + 1) should be present.
            let size = journal.size().await;
            assert_eq!(*size, 8);

            // Verify the actual items at each location.
            let (_, ops) = journal.proof(Location::new(2), NZU64!(6)).await.unwrap();
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(*op, create_operation((i + 3) as u8));
            }
        });
    }

    /// finalize_from panics when items_to_skip exceeds total items.
    #[test_traced("INFO")]
    #[should_panic(expected = "items_to_skip exceeds total items in chain")]
    fn test_finalize_from_skip_too_many() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "ff-panic", 5).await;

            let merkleized = journal.new_batch().add(create_operation(10)).merkleize();

            // items has 1 item, but we try to skip 5.
            let _ = merkleized.finalize_from(journal.mmr.size(), 5);
        });
    }
}
