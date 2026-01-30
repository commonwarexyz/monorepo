//! Authenticated journal implementation.
//!
//! An authenticated journal maintains a contiguous journal of items alongside a Merkle Mountain
//! Range (MMR). The item at index i in the journal corresponds to the leaf at Location i in the
//! MMR. This structure enables efficient proofs that an item is included in the journal at a
//! specific location.

use crate::{
    journal::{
        contiguous::{fixed, variable, Contiguous, MutableContiguous},
        Error as JournalError,
    },
    mmr::{
        journaled::{CleanMmr, Mmr},
        mem::{Clean, Dirty, State},
        Location, Position, Proof, StandardHasher,
    },
    Persistable,
};
use commonware_codec::{CodecFixedShared, CodecShared, Encode, EncodeShared};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use core::num::{NonZeroU64, NonZeroUsize};
use futures::{future::try_join_all, try_join, TryFutureExt as _};
use thiserror::Error;
use tracing::{debug, warn};

/// Errors that can occur when interacting with an authenticated journal.
#[derive(Error, Debug)]
pub enum Error {
    #[error("mmr error: {0}")]
    Mmr(#[from] crate::mmr::Error),

    #[error("journal error: {0}")]
    Journal(#[from] super::Error),
}
/// An append-only data structure that maintains a sequential journal of items alongside a Merkle
/// Mountain Range (MMR). The item at index i in the journal corresponds to the leaf at Location i
/// in the MMR. This structure enables efficient proofs that an item is included in the journal at a
/// specific location.
pub struct Journal<E, C, H, S: State<H::Digest> + Send + Sync = Dirty>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// MMR where each leaf is an item digest.
    /// Invariant: leaf i corresponds to item i in the journal.
    pub(crate) mmr: Mmr<E, H::Digest, S>,

    /// Journal of items.
    /// Invariant: item i corresponds to leaf i in the MMR.
    pub(crate) journal: C,

    pub(crate) hasher: StandardHasher<H>,
}

impl<E, C, H, S> Journal<E, C, H, S>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
    S: State<DigestOf<H>> + Send + Sync,
{
    /// Returns the number of items in the journal.
    pub fn size(&self) -> Location {
        Location::new_unchecked(self.journal.size())
    }

    /// Returns the oldest retained location in the journal.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.journal
            .oldest_retained_pos()
            .map(Location::new_unchecked)
    }

    /// Returns the pruning boundary for the journal.
    pub fn pruning_boundary(&self) -> Location {
        self.journal.pruning_boundary().into()
    }

    /// Read an item from the journal at the given location.
    pub async fn read(&self, loc: Location) -> Result<C::Item, Error> {
        self.journal.read(*loc).await.map_err(Error::Journal)
    }
}

impl<E, C, H, S> Journal<E, C, H, S>
where
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item: EncodeShared>,
    H: Hasher,
    S: State<DigestOf<H>> + Send + Sync,
{
    pub async fn append(&mut self, item: C::Item) -> Result<Location, Error> {
        let encoded_item = item.encode();

        // Append item to the journal and update the MMR in parallel.
        let (_, loc) = try_join!(
            self.mmr
                .add(&mut self.hasher, &encoded_item)
                .map_err(Error::Mmr),
            self.journal.append(item).map_err(Into::into)
        )?;

        Ok(Location::new_unchecked(loc))
    }
}

impl<E, C, H, S> Journal<E, C, H, S>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item: EncodeShared> + Persistable<Error = JournalError>,
    H: Hasher,
    S: State<DigestOf<H>> + Send + Sync,
{
    /// Durably persist the journal. This is faster than `sync()` but does not persist the MMR,
    /// meaning recovery will be required on startup if we crash before `sync()`.
    pub async fn commit(&mut self) -> Result<(), Error> {
        self.journal.commit().await.map_err(Error::Journal)
    }
}

impl<E, C, H> Journal<E, C, H, Clean<H::Digest>>
where
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// Create a new [Journal] from the given components after aligning the MMR with the journal.
    pub async fn from_components(
        mmr: CleanMmr<E, H::Digest>,
        journal: C,
        mut hasher: StandardHasher<H>,
        apply_batch_size: u64,
    ) -> Result<Self, Error> {
        let mut mmr = Self::align(mmr, &journal, &mut hasher, apply_batch_size).await?;

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
        mut mmr: CleanMmr<E, H::Digest>,
        journal: &C,
        hasher: &mut StandardHasher<H>,
        apply_batch_size: u64,
    ) -> Result<CleanMmr<E, H::Digest>, Error> {
        // Pop any MMR elements that are ahead of the journal.
        // Note mmr_size is the size of the MMR in leaves, not positions.
        let journal_size = journal.size();
        let mut mmr_size = mmr.leaves();
        if mmr_size > journal_size {
            let pop_count = mmr_size - journal_size;
            warn!(journal_size, ?pop_count, "popping MMR items");
            mmr.pop(hasher, *pop_count as usize).await?;
            mmr_size = Location::new_unchecked(journal_size);
        }

        // If the MMR is behind, replay journal items to catch up.
        if mmr_size < journal_size {
            let replay_count = journal_size - *mmr_size;
            warn!(
                journal_size,
                replay_count, "MMR lags behind journal, replaying journal to catch up"
            );

            let mut mmr = mmr.into_dirty();
            let mut batch_size = 0;
            while mmr_size < journal_size {
                let op = journal.read(*mmr_size).await?;
                mmr.add(hasher, &op.encode()).await?;
                mmr_size += 1;
                batch_size += 1;
                if batch_size >= apply_batch_size {
                    mmr = mmr.merkleize(hasher).into_dirty();
                    batch_size = 0;
                }
            }
            return Ok(mmr.merkleize(hasher));
        }

        // At this point the MMR and journal should be consistent.
        assert_eq!(journal.size(), mmr.leaves());

        Ok(mmr)
    }

    /// Prune both the MMR and journal to the given location.
    ///
    /// # Returns
    /// The new pruning boundary, which may be less than the requested `prune_loc`.
    pub async fn prune(&mut self, prune_loc: Location) -> Result<Location, Error> {
        if self.mmr.size() == 0 {
            // DB is empty, nothing to prune.
            return Ok(self.pruning_boundary());
        }

        // Sync the mmr before pruning the journal, otherwise the MMR tip could end up behind the
        // journal's pruning boundary on restart from an unclean shutdown, and there would be no way
        // to replay the items between the MMR tip and the journal pruning boundary.
        self.mmr.sync().await?;

        // Prune the journal and check if anything was actually pruned
        if !self.journal.prune(*prune_loc).await? {
            return Ok(self.pruning_boundary());
        }

        let pruning_boundary = self.pruning_boundary();
        let size = self.size();
        debug!(?size, ?prune_loc, ?pruning_boundary, "pruned inactive ops");

        // Prune MMR to match the journal's actual boundary
        self.mmr
            .prune_to_pos(Position::try_from(pruning_boundary)?)
            .await?;

        Ok(pruning_boundary)
    }
}

impl<E, C, H> Journal<E, C, H, Clean<H::Digest>>
where
    E: Storage + Clock + Metrics,
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
    /// - Returns [Error::Mmr] with [crate::mmr::Error::LocationOverflow] if `start_loc` >
    ///   [crate::mmr::MAX_LOCATION].
    /// - Returns [Error::Mmr] with [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= current
    ///   item count.
    /// - Returns [Error::Journal] with [crate::journal::Error::ItemPruned] if `start_loc` has been
    ///   pruned.
    pub async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<C::Item>), Error> {
        self.historical_proof(self.size(), start_loc, max_ops).await
    }

    /// Generate a historical proof with respect to the state of the MMR when it had
    /// `historical_leaves` leaves.
    ///
    /// Returns a proof and the items corresponding to the leaves in the range `start_loc..end_loc`,
    /// where `end_loc` is the minimum of `historical_leaves` and `start_loc + max_ops`.
    ///
    /// # Errors
    ///
    /// - Returns [Error::Mmr] with [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >=
    ///   `historical_leaves` or `historical_leaves` > number of items in the journal.
    /// - Returns [Error::Journal] with [crate::journal::Error::ItemPruned] if `start_loc` has been
    ///   pruned.
    pub async fn historical_proof(
        &self,
        historical_leaves: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<C::Item>), Error> {
        let leaves = self.size();
        if historical_leaves > leaves {
            return Err(crate::mmr::Error::RangeOutOfBounds(leaves).into());
        }
        if start_loc >= historical_leaves {
            return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
        }
        let end_loc = std::cmp::min(historical_leaves, start_loc.saturating_add(max_ops.get()));

        let proof = self
            .mmr
            .historical_range_proof(historical_leaves, start_loc..end_loc)
            .await?;

        let mut ops = Vec::with_capacity((*end_loc - *start_loc) as usize);
        let futures = (*start_loc..*end_loc)
            .map(|i| self.journal.read(i))
            .collect::<Vec<_>>();
        try_join_all(futures)
            .await?
            .into_iter()
            .for_each(|op| ops.push(op));

        Ok((proof, ops))
    }

    /// Return the root of the MMR.
    pub const fn root(&self) -> H::Digest {
        self.mmr.root()
    }

    /// Convert this journal into its dirty counterpart for batched updates.
    pub fn into_dirty(self) -> Journal<E, C, H, Dirty> {
        Journal {
            mmr: self.mmr.into_dirty(),
            journal: self.journal,
            hasher: self.hasher,
        }
    }
}

impl<E, C, H> Journal<E, C, H, Clean<H::Digest>>
where
    E: Storage + Clock + Metrics,
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
    pub async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.journal.sync().map_err(Error::Journal),
            self.mmr.sync().map_err(Into::into)
        )?;

        Ok(())
    }
}

impl<E, C, H> Journal<E, C, H, Dirty>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// Merkleize the journal and compute the root digest.
    pub fn merkleize(self) -> Journal<E, C, H, Clean<H::Digest>> {
        let Self {
            mmr,
            journal,
            mut hasher,
        } = self;
        Journal {
            mmr: mmr.merkleize(&mut hasher),
            journal,
            hasher,
        }
    }
}

impl<E, C, H> Journal<E, C, H, Dirty>
where
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item: EncodeShared>,
    H: Hasher,
{
    /// Create a new dirty journal from aligned components.
    pub async fn from_components(
        mmr: CleanMmr<E, H::Digest>,
        journal: C,
        hasher: StandardHasher<H>,
        apply_batch_size: u64,
    ) -> Result<Self, Error> {
        let clean = Journal::<E, C, H, Clean<H::Digest>>::from_components(
            mmr,
            journal,
            hasher,
            apply_batch_size,
        )
        .await?;
        Ok(clean.into_dirty())
    }
}

/// The number of items to apply to the MMR in a single batch.
const APPLY_BATCH_SIZE: u64 = 1 << 16;

impl<E, O, H> Journal<E, fixed::Journal<E, O>, H, Clean<H::Digest>>
where
    E: Storage + Clock + Metrics,
    O: CodecFixedShared,
    H: Hasher,
{
    /// Create a new [Journal] for fixed-length items.
    ///
    /// The journal will be rewound to the last item that matches the `rewind_predicate` on
    /// initialization.
    pub async fn new(
        context: E,
        mmr_cfg: crate::mmr::journaled::Config,
        journal_cfg: fixed::Config,
        rewind_predicate: fn(&O) -> bool,
    ) -> Result<Self, Error> {
        let mut journal = fixed::Journal::init(context.with_label("journal"), journal_cfg).await?;

        // Rewind journal to last matching item.
        journal.rewind_to(rewind_predicate).await?;

        // Align the MMR and journal.
        let mut hasher = StandardHasher::<H>::new();
        let mmr = Mmr::init(context.with_label("mmr"), &mut hasher, mmr_cfg).await?;
        let mut mmr = Self::align(mmr, &journal, &mut hasher, APPLY_BATCH_SIZE).await?;

        // Sync the journal and MMR to disk to avoid having to repeat any recovery that may have
        // been performed on next startup.
        journal.sync().await?;
        mmr.sync().await?;

        Ok(Self {
            mmr,
            journal,
            hasher,
        })
    }
}

impl<E, O, H> Journal<E, variable::Journal<E, O>, H, Clean<H::Digest>>
where
    E: Storage + Clock + Metrics,
    O: CodecShared,
    H: Hasher,
{
    /// Create a new [Journal] for variable-length items.
    ///
    /// The journal will be rewound to the last item that matches the `rewind_predicate` on
    /// initialization.
    pub async fn new(
        context: E,
        mmr_cfg: crate::mmr::journaled::Config,
        journal_cfg: variable::Config<O::Cfg>,
        rewind_predicate: fn(&O) -> bool,
    ) -> Result<Self, Error> {
        let mut hasher = StandardHasher::<H>::new();
        let mmr = Mmr::init(context.with_label("mmr"), &mut hasher, mmr_cfg).await?;
        let mut journal =
            variable::Journal::init(context.with_label("journal"), journal_cfg).await?;

        // Rewind to last matching item.
        journal.rewind_to(rewind_predicate).await?;

        // Align the MMR and journal.
        let mut mmr = Self::align(mmr, &journal, &mut hasher, APPLY_BATCH_SIZE).await?;

        // Sync the journal and MMR to disk to avoid having to repeat any recovery that may have
        // been performed on next startup.
        journal.sync().await?;
        mmr.sync().await?;

        Ok(Self {
            mmr,
            journal,
            hasher,
        })
    }
}

impl<E, C, H, S> Contiguous for Journal<E, C, H, S>
where
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item: EncodeShared>,
    H: Hasher,
    S: State<DigestOf<H>> + Send + Sync,
{
    type Item = C::Item;

    fn size(&self) -> u64 {
        self.journal.size()
    }

    fn oldest_retained_pos(&self) -> Option<u64> {
        self.journal.oldest_retained_pos()
    }

    fn pruning_boundary(&self) -> u64 {
        self.journal.pruning_boundary()
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<
        impl futures::Stream<Item = Result<(u64, Self::Item), JournalError>> + '_,
        JournalError,
    > {
        self.journal.replay(start_pos, buffer).await
    }

    async fn read(&self, position: u64) -> Result<Self::Item, JournalError> {
        self.journal.read(position).await
    }
}

impl<E, C, H> MutableContiguous for Journal<E, C, H, Dirty>
where
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item: EncodeShared>,
    H: Hasher,
{
    async fn append(&mut self, item: Self::Item) -> Result<u64, JournalError> {
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
                .pop((leaves - size) as usize)
                .await
                .map_err(|error| JournalError::Mmr(anyhow::Error::from(error)))?;
        }

        Ok(())
    }
}

impl<E, C, H> MutableContiguous for Journal<E, C, H, Clean<H::Digest>>
where
    E: Storage + Clock + Metrics,
    C: MutableContiguous<Item: EncodeShared>,
    H: Hasher,
{
    async fn append(&mut self, item: Self::Item) -> Result<u64, JournalError> {
        let loc = self.append(item).await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Mmr(inner) => JournalError::Mmr(anyhow::Error::from(inner)),
        })?;

        Ok(*loc)
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, JournalError> {
        let old_pruning_boundary = self.pruning_boundary();
        let pruning_boundary = self
            .prune(Location::new_unchecked(min_position))
            .await
            .map_err(|e| match e {
                Error::Journal(inner) => inner,
                Error::Mmr(inner) => JournalError::Mmr(anyhow::Error::from(inner)),
            })?;

        Ok(old_pruning_boundary != pruning_boundary)
    }

    async fn rewind(&mut self, size: u64) -> Result<(), JournalError> {
        self.journal.rewind(size).await?;

        let leaves = *self.mmr.leaves();
        if leaves > size {
            self.mmr
                .pop(&mut self.hasher, (leaves - size) as usize)
                .await
                .map_err(|error| JournalError::Mmr(anyhow::Error::from(error)))?;
        }

        Ok(())
    }
}

impl<E, C, H> Persistable for Journal<E, C, H, Clean<H::Digest>>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item: EncodeShared> + Persistable<Error = JournalError>,
    H: Hasher,
{
    type Error = JournalError;

    async fn commit(&mut self) -> Result<(), JournalError> {
        self.commit().await.map_err(|e| match e {
            Error::Journal(inner) => inner,
            Error::Mmr(inner) => JournalError::Mmr(anyhow::Error::from(inner)),
        })
    }

    async fn sync(&mut self) -> Result<(), JournalError> {
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
        Metrics, Runner as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use futures::StreamExt as _;
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    /// Create MMR configuration for tests.
    fn mmr_config(suffix: &str) -> MmrConfig {
        MmrConfig {
            journal_partition: format!("mmr_journal_{suffix}"),
            metadata_partition: format!("mmr_metadata_{suffix}"),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Create journal configuration for tests.
    fn journal_config(suffix: &str) -> JConfig {
        JConfig {
            partition: format!("journal_{suffix}"),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    type AuthenticatedJournal = Journal<
        deterministic::Context,
        ContiguousJournal<deterministic::Context, Operation<Digest, Digest>>,
        Sha256,
        Clean<sha256::Digest>,
    >;

    /// Create a new empty authenticated journal.
    async fn create_empty_journal(context: Context, suffix: &str) -> AuthenticatedJournal {
        AuthenticatedJournal::new(
            context,
            mmr_config(suffix),
            journal_config(suffix),
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
            let loc = journal.append(op).await.unwrap();
            assert_eq!(loc, Location::new_unchecked(i as u64));
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
        CleanMmr<deterministic::Context, sha256::Digest>,
        ContiguousJournal<deterministic::Context, Operation<Digest, Digest>>,
        StandardHasher<Sha256>,
    ) {
        let mut hasher = StandardHasher::new();
        let mmr = Mmr::init(context.with_label("mmr"), &mut hasher, mmr_config(suffix))
            .await
            .unwrap();
        let journal =
            ContiguousJournal::init(context.with_label("journal"), journal_config(suffix))
                .await
                .unwrap();
        (mmr, journal, hasher)
    }

    /// Verify that a proof correctly proves the given operations are included in the MMR.
    fn verify_proof(
        proof: &crate::mmr::Proof<<Sha256 as commonware_cryptography::Hasher>::Digest>,
        operations: &[Operation<Digest, Digest>],
        start_loc: Location,
        root: &<Sha256 as commonware_cryptography::Hasher>::Digest,
        hasher: &mut StandardHasher<Sha256>,
    ) -> bool {
        let encoded_ops: Vec<_> = operations.iter().map(|op| op.encode()).collect();
        proof.verify_range_inclusion(hasher, &encoded_ops, start_loc, root)
    }

    /// Verify that new() creates an empty authenticated journal.
    #[test_traced("INFO")]
    fn test_new_creates_empty_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_empty_journal(context, "new_empty").await;

            assert_eq!(journal.size(), 0);
            assert_eq!(journal.pruning_boundary(), 0);
            assert_eq!(journal.oldest_retained_pos(), None);
        });
    }

    /// Verify that align() correctly handles empty MMR and journal components.
    #[test_traced("INFO")]
    fn test_align_with_empty_mmr_and_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, journal, mut hasher) = create_components(context, "align_empty").await;

            let mmr = Journal::align(mmr, &journal, &mut hasher, APPLY_BATCH_SIZE)
                .await
                .unwrap();

            assert_eq!(mmr.leaves(), Location::new_unchecked(0));
            assert_eq!(journal.size(), Location::new_unchecked(0));
        });
    }

    /// Verify that align() pops MMR elements when MMR is ahead of the journal.
    #[test_traced("WARN")]
    fn test_align_when_mmr_ahead() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut mmr, mut journal, mut hasher) = create_components(context, "mmr_ahead").await;

            // Add 20 operations to both MMR and journal
            for i in 0..20 {
                let op = create_operation(i as u8);
                let encoded = op.encode();
                mmr.add(&mut hasher, &encoded).await.unwrap();
                journal.append(op).await.unwrap();
            }

            // Add commit operation to journal only (making journal ahead)
            let commit_op = Operation::CommitFloor(None, Location::new_unchecked(0));
            journal.append(commit_op).await.unwrap();
            journal.sync().await.unwrap();

            // MMR has 20 leaves, journal has 21 operations (20 ops + 1 commit)
            let mmr = Journal::align(mmr, &journal, &mut hasher, APPLY_BATCH_SIZE)
                .await
                .unwrap();

            // MMR should have been popped to match journal
            assert_eq!(mmr.leaves(), Location::new_unchecked(21));
            assert_eq!(journal.size(), Location::new_unchecked(21));
        });
    }

    /// Verify that align() replays journal operations when journal is ahead of MMR.
    #[test_traced("WARN")]
    fn test_align_when_journal_ahead() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut mmr, mut journal, mut hasher) =
                create_components(context, "journal_ahead").await;

            // Add 20 operations to journal only
            for i in 0..20 {
                let op = create_operation(i as u8);
                journal.append(op).await.unwrap();
            }

            // Add commit
            let commit_op = Operation::CommitFloor(None, Location::new_unchecked(0));
            journal.append(commit_op).await.unwrap();
            journal.sync().await.unwrap();

            // Journal has 21 operations, MMR has 0 leaves
            mmr = Journal::align(mmr, &journal, &mut hasher, APPLY_BATCH_SIZE)
                .await
                .unwrap();

            // MMR should have been replayed to match journal
            assert_eq!(mmr.leaves(), Location::new_unchecked(21));
            assert_eq!(journal.size(), Location::new_unchecked(21));
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
                let loc = journal.append(create_operation(i as u8)).await.unwrap();
                assert_eq!(loc, Location::new_unchecked(i as u64));
            }

            // Don't sync - these are uncommitted
            // After alignment, they should be discarded
            let size_before = journal.size();
            assert_eq!(size_before, 20);

            // Drop and recreate to simulate restart (which calls align internally)
            journal.sync().await.unwrap();
            drop(journal);
            let journal = create_empty_journal(context.with_label("second"), "mismatched").await;

            // Uncommitted operations should be gone
            assert_eq!(journal.size(), 0);
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
                    journal_config("rewind_match"),
                )
                .await
                .unwrap();

                // Add operations where operation 3 is a commit
                for i in 0..3 {
                    journal.append(create_operation(i)).await.unwrap();
                }
                journal
                    .append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                    .await
                    .unwrap();
                for i in 4..7 {
                    journal.append(create_operation(i)).await.unwrap();
                }

                // Rewind to last commit
                let final_size = journal.rewind_to(|op| op.is_commit()).await.unwrap();
                assert_eq!(final_size, 4);
                assert_eq!(journal.size(), 4);

                // Verify the commit operation is still there
                let op = journal.read(3).await.unwrap();
                assert!(op.is_commit());
            }

            // Test 2: Last matching operation is chosen when multiple match
            {
                let mut journal = ContiguousJournal::init(
                    context.with_label("rewind_multiple"),
                    journal_config("rewind_multiple"),
                )
                .await
                .unwrap();

                // Add multiple commits
                journal.append(create_operation(0)).await.unwrap();
                journal
                    .append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                    .await
                    .unwrap(); // pos 1
                journal.append(create_operation(2)).await.unwrap();
                journal
                    .append(Operation::CommitFloor(None, Location::new_unchecked(1)))
                    .await
                    .unwrap(); // pos 3
                journal.append(create_operation(4)).await.unwrap();

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
                    journal_config("rewind_no_match"),
                )
                .await
                .unwrap();

                // Add operations with no commits
                for i in 0..10 {
                    journal.append(create_operation(i)).await.unwrap();
                }

                // Rewind should go to pruning boundary (0 for unpruned)
                let final_size = journal.rewind_to(|op| op.is_commit()).await.unwrap();
                assert_eq!(final_size, 0, "Should rewind to pruning boundary (0)");
                assert_eq!(journal.size(), 0);
            }

            // Test 4: Rewind with existing pruning boundary
            {
                let mut journal = ContiguousJournal::init(
                    context.with_label("rewind_with_pruning"),
                    journal_config("rewind_with_pruning"),
                )
                .await
                .unwrap();

                // Add operations and a commit at position 10 (past first section boundary of 7)
                for i in 0..10 {
                    journal.append(create_operation(i)).await.unwrap();
                }
                journal
                    .append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                    .await
                    .unwrap(); // pos 10
                for i in 11..15 {
                    journal.append(create_operation(i)).await.unwrap();
                }
                journal.sync().await.unwrap();

                // Prune up to position 8 (this will prune section 0, items 0-6, keeping 7+)
                journal.prune(8).await.unwrap();
                let oldest = journal.oldest_retained_pos();
                assert_eq!(oldest, Some(7));

                // Add more uncommitted operations
                for i in 15..20 {
                    journal.append(create_operation(i)).await.unwrap();
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
                    journal_config("rewind_no_match_pruned"),
                )
                .await
                .unwrap();

                // Add operations with a commit at position 5 (in section 0: 0-6)
                for i in 0..5 {
                    journal.append(create_operation(i)).await.unwrap();
                }
                journal
                    .append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                    .await
                    .unwrap(); // pos 5
                for i in 6..10 {
                    journal.append(create_operation(i)).await.unwrap();
                }
                journal.sync().await.unwrap();

                // Prune up to position 8 (this prunes section 0, including the commit at pos 5)
                // Pruning boundary will be at position 7 (start of section 1)
                journal.prune(8).await.unwrap();
                let oldest = journal.oldest_retained_pos();
                assert_eq!(oldest, Some(7));

                // Add uncommitted operations with no commits (in section 1: 7-13)
                for i in 10..14 {
                    journal.append(create_operation(i)).await.unwrap();
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
                    journal_config("rewind_empty"),
                )
                .await
                .unwrap();

                // Rewind empty journal should be no-op
                let final_size = journal
                    .rewind_to(|op: &Operation<Digest, Digest>| op.is_commit())
                    .await
                    .unwrap();
                assert_eq!(final_size, 0);
                assert_eq!(journal.size(), 0);
            }

            // Test 7: Position based authenticated journal rewind.
            {
                let mut journal = AuthenticatedJournal::new(
                    context,
                    mmr_config("rewind"),
                    journal_config("rewind"),
                    |op| op.is_commit(),
                )
                .await
                .unwrap();

                // Add operations with a commit at position 5 (in section 0: 0-6)
                for i in 0..5 {
                    journal.append(create_operation(i)).await.unwrap();
                }
                journal
                    .append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                    .await
                    .unwrap(); // pos 5
                for i in 6..10 {
                    journal.append(create_operation(i)).await.unwrap();
                }
                assert_eq!(journal.size(), 10);

                journal.rewind(2).await.unwrap();
                assert_eq!(journal.size(), 2);
                assert_eq!(journal.mmr.leaves(), 2);
                assert_eq!(journal.mmr.size(), 3);
                assert_eq!(journal.pruning_boundary(), 0);
                assert_eq!(journal.oldest_retained_pos(), Some(0));

                assert!(matches!(
                    journal.rewind(3).await,
                    Err(JournalError::InvalidRewind(_))
                ));

                journal.rewind(0).await.unwrap();
                assert_eq!(journal.size(), 0);
                assert_eq!(journal.mmr.leaves(), 0);
                assert_eq!(journal.mmr.size(), 0);
                assert_eq!(journal.pruning_boundary(), 0);
                assert_eq!(journal.oldest_retained_pos(), None);

                // Test rewinding after pruning.
                for i in 0..255 {
                    journal.append(create_operation(i)).await.unwrap();
                }
                MutableContiguous::prune(&mut journal, 100).await.unwrap();
                assert_eq!(journal.pruning_boundary(), 98);
                let res = journal.rewind(97).await;
                assert!(matches!(res, Err(JournalError::InvalidRewind(97))));
                journal.rewind(98).await.unwrap();
                assert_eq!(journal.size(), 98);
                assert_eq!(journal.mmr.leaves(), 98);
                assert_eq!(journal.pruning_boundary(), 98);
                assert_eq!(journal.oldest_retained_pos(), None);
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

            assert_eq!(journal.size(), 0);

            // Add 50 operations
            let expected_ops: Vec<_> = (0..50).map(|i| create_operation(i as u8)).collect();
            for (i, op) in expected_ops.iter().enumerate() {
                let loc = journal.append(op.clone()).await.unwrap();
                assert_eq!(loc, Location::new_unchecked(i as u64));
                assert_eq!(journal.size(), (i + 1) as u64);
            }

            assert_eq!(journal.size(), 50);

            // Verify all operations can be read back correctly
            journal.sync().await.unwrap();
            for (i, expected_op) in expected_ops.iter().enumerate() {
                let read_op = journal
                    .read(Location::new_unchecked(i as u64))
                    .await
                    .unwrap();
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
            let first_op = journal.read(Location::new_unchecked(0)).await.unwrap();
            assert_eq!(first_op, create_operation(0));

            // Verify reading middle operation
            let middle_op = journal.read(Location::new_unchecked(25)).await.unwrap();
            assert_eq!(middle_op, create_operation(25));

            // Verify reading last operation
            let last_op = journal.read(Location::new_unchecked(49)).await.unwrap();
            assert_eq!(last_op, create_operation(49));

            // Verify all operations match expected values
            for i in 0..50 {
                let op = journal.read(Location::new_unchecked(i)).await.unwrap();
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
                .append(Operation::CommitFloor(None, Location::new_unchecked(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();
            let pruned_boundary = journal.prune(Location::new_unchecked(50)).await.unwrap();

            // Try to read an operation before the pruned boundary
            let read_loc = Location::new_unchecked(0);
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
            let result = journal.read(Location::new_unchecked(10)).await;
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

            assert_eq!(journal.size(), 50);

            // Verify all operations can be read back and match expected values
            for i in 0..50 {
                let op = journal.read(Location::new_unchecked(i)).await.unwrap();
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
                let loc = journal.append(op.clone()).await.unwrap();
                assert_eq!(loc, Location::new_unchecked(i as u64),);
            }

            // Add commit operation to commit the operations
            let commit_loc = journal
                .append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await
                .unwrap();
            assert_eq!(
                commit_loc,
                Location::new_unchecked(20),
                "commit should be at location 20"
            );
            journal.sync().await.unwrap();

            // Reopen and verify the operations persisted
            drop(journal);
            let journal = create_empty_journal(context.with_label("second"), "close_pending").await;
            assert_eq!(journal.size(), 21);

            // Verify all operations can be read back
            for (i, expected_op) in expected_ops.iter().enumerate() {
                let read_op = journal
                    .read(Location::new_unchecked(i as u64))
                    .await
                    .unwrap();
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

            let boundary = journal.prune(Location::new_unchecked(0)).await.unwrap();

            assert_eq!(boundary, Location::new_unchecked(0));
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
                .append(Operation::CommitFloor(None, Location::new_unchecked(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let boundary = journal.prune(Location::new_unchecked(50)).await.unwrap();

            // Boundary should be <= requested location (may align to section boundary)
            assert!(boundary <= Location::new_unchecked(50));
        });
    }

    /// Verify that prune() returns the actual boundary (which may differ from requested).
    #[test_traced("INFO")]
    fn test_prune_returns_actual_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "prune_boundary", 100).await;

            journal
                .append(Operation::CommitFloor(None, Location::new_unchecked(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let requested = Location::new_unchecked(50);
            let actual = journal.prune(requested).await.unwrap();

            // Actual boundary should match oldest_retained_loc
            let oldest = journal.oldest_retained_loc().unwrap();
            assert_eq!(actual, oldest);

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
                .append(Operation::CommitFloor(None, Location::new_unchecked(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let count_before = journal.size();
            journal.prune(Location::new_unchecked(50)).await.unwrap();
            let count_after = journal.size();

            assert_eq!(count_before, count_after);
        });
    }

    /// Verify oldest_retained_loc() for empty journal, no pruning, and after pruning.
    #[test_traced("INFO")]
    fn test_oldest_retained_loc() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test empty journal
            let journal = create_empty_journal(context.with_label("empty"), "oldest").await;
            let oldest = journal.oldest_retained_loc();
            assert_eq!(oldest, None);

            // Test no pruning
            let journal =
                create_journal_with_ops(context.with_label("no_prune"), "oldest", 100).await;
            let oldest = journal.oldest_retained_loc();
            assert_eq!(oldest, Some(Location::new_unchecked(0)));

            // Test after pruning
            let mut journal =
                create_journal_with_ops(context.with_label("pruned"), "oldest", 100).await;
            journal
                .append(Operation::CommitFloor(None, Location::new_unchecked(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let pruned_boundary = journal.prune(Location::new_unchecked(50)).await.unwrap();

            let oldest_loc = journal.oldest_retained_loc().unwrap();
            // Should match the pruned boundary (may be <= 50 due to section alignment)
            assert_eq!(oldest_loc, pruned_boundary);
            // Should be <= requested location (50)
            assert!(oldest_loc <= Location::new_unchecked(50));
        });
    }

    /// Verify pruning_boundary() for empty journal, no pruning, and after pruning.
    #[test_traced("INFO")]
    fn test_pruning_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test empty journal
            let journal = create_empty_journal(context.with_label("empty"), "boundary").await;
            let boundary = journal.pruning_boundary();
            assert_eq!(boundary, Location::new_unchecked(0));

            // Test no pruning
            let journal =
                create_journal_with_ops(context.with_label("no_prune"), "boundary", 100).await;
            let boundary = journal.pruning_boundary();
            assert_eq!(boundary, Location::new_unchecked(0));

            // Test after pruning
            let mut journal =
                create_journal_with_ops(context.with_label("pruned"), "boundary", 100).await;
            journal
                .append(Operation::CommitFloor(None, Location::new_unchecked(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let pruned_boundary = journal.prune(Location::new_unchecked(50)).await.unwrap();

            let boundary = journal.pruning_boundary();
            assert_eq!(boundary, pruned_boundary);
        });
    }

    /// Verify that MMR prunes to the journal's actual boundary, not the requested location.
    #[test_traced("INFO")]
    fn test_mmr_prunes_to_journal_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "mmr_boundary", 50).await;

            journal
                .append(Operation::CommitFloor(None, Location::new_unchecked(25)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let pruned_boundary = journal.prune(Location::new_unchecked(25)).await.unwrap();

            // Verify MMR and journal remain in sync
            let oldest_retained = journal.oldest_retained_loc();
            assert_eq!(Some(pruned_boundary), oldest_retained);

            // Verify boundary is at or before requested (due to section alignment)
            assert!(pruned_boundary <= Location::new_unchecked(25));

            // Verify operation count is unchanged
            assert_eq!(journal.size(), 51);
        });
    }

    /// Verify proof() for multiple operations.
    #[test_traced("INFO")]
    fn test_proof_multiple_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_multi", 50).await;

            let (proof, ops) = journal
                .proof(Location::new_unchecked(0), NZU64!(50))
                .await
                .unwrap();

            assert_eq!(ops.len(), 50);
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(*op, create_operation(i as u8));
            }

            // Verify the proof is valid
            let mut hasher = StandardHasher::new();
            let root = journal.root();
            assert!(verify_proof(
                &proof,
                &ops,
                Location::new_unchecked(0),
                &root,
                &mut hasher
            ));
        });
    }

    /// Verify that historical_proof() respects the max_ops limit.
    #[test_traced("INFO")]
    fn test_historical_proof_limited_by_max_ops() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_limit", 50).await;

            let size = journal.size();
            let (proof, ops) = journal
                .historical_proof(size, Location::new_unchecked(0), NZU64!(20))
                .await
                .unwrap();

            // Should return only 20 operations despite 50 being available
            assert_eq!(ops.len(), 20);
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(*op, create_operation(i as u8));
            }

            // Verify the proof is valid
            let mut hasher = StandardHasher::new();
            let root = journal.root();
            assert!(verify_proof(
                &proof,
                &ops,
                Location::new_unchecked(0),
                &root,
                &mut hasher
            ));
        });
    }

    /// Verify historical_proof() at the end of the journal.
    #[test_traced("INFO")]
    fn test_historical_proof_at_end_of_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_end", 50).await;

            let size = journal.size();
            // Request proof starting near the end
            let (proof, ops) = journal
                .historical_proof(size, Location::new_unchecked(40), NZU64!(20))
                .await
                .unwrap();

            // Should return only 10 operations (positions 40-49)
            assert_eq!(ops.len(), 10);
            for (i, op) in ops.iter().enumerate() {
                assert_eq!(*op, create_operation((40 + i) as u8));
            }

            // Verify the proof is valid
            let mut hasher = StandardHasher::new();
            let root = journal.root();
            assert!(verify_proof(
                &proof,
                &ops,
                Location::new_unchecked(40),
                &root,
                &mut hasher
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
                .historical_proof(
                    Location::new_unchecked(10),
                    Location::new_unchecked(0),
                    NZU64!(1),
                )
                .await;

            assert!(matches!(
                result,
                Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
            ));
        });
    }

    /// Verify that historical_proof() returns an error when start_loc >= size.
    #[test_traced("INFO")]
    fn test_historical_proof_start_too_large_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_start_oob", 5).await;

            let size = journal.size();
            // Request proof starting at size (should fail)
            let result = journal.historical_proof(size, size, NZU64!(1)).await;

            assert!(matches!(
                result,
                Err(Error::Mmr(crate::mmr::Error::RangeOutOfBounds(_)))
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
            let mut hasher = StandardHasher::new();
            let historical_root = journal.root();
            let historical_size = journal.size();

            // Add more operations after the historical state
            for i in 50..100 {
                journal.append(create_operation(i as u8)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Generate proof for the historical state
            let (proof, ops) = journal
                .historical_proof(historical_size, Location::new_unchecked(0), NZU64!(50))
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
                Location::new_unchecked(0),
                &historical_root,
                &mut hasher
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
                .append(Operation::CommitFloor(None, Location::new_unchecked(25)))
                .await
                .unwrap();
            journal.sync().await.unwrap();
            let pruned_boundary = journal.prune(Location::new_unchecked(25)).await.unwrap();

            // Try to get proof starting at a location before the pruned boundary
            let size = journal.size();
            let start_loc = Location::new_unchecked(0);
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
            let stream = journal.replay(0, NZUsize!(10)).await.unwrap();
            futures::pin_mut!(stream);
            assert!(stream.next().await.is_none());

            // Test replaying all operations
            let journal =
                create_journal_with_ops(context.with_label("with_ops"), "replay", 50).await;
            let stream = journal.replay(0, NZUsize!(100)).await.unwrap();
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
            let stream = journal.replay(25, NZUsize!(100)).await.unwrap();
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
}
