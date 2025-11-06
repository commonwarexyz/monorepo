//! Authenticated journal implementation.
//!
//! An authenticated journal maintains a contiguous journal of operations alongside a Merkle Mountain
//! Range (MMR). The operation at index i in the journal corresponds to the leaf at Location i in the
//! MMR. This structure enables efficient proofs that an operation is included in the journal at a
//! specific location.

use crate::{
    journal::contiguous::{fixed, variable, Contiguous},
    mmr::{journaled::Mmr, Location, Position, Proof, StandardHasher},
};
use commonware_codec::{Codec, CodecFixed, Encode};
use commonware_cryptography::Hasher;
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

/// Rewinds the journal to the last operation matching the rewind predicate. If no operation
/// matches the predicate, rewinds to the pruning boundary, discarding all unpruned operations.
async fn rewind<O>(
    journal: &mut impl Contiguous<Item = O>,
    rewind_predicate: fn(&O) -> bool,
) -> Result<u64, Error> {
    let journal_size = journal.size();
    let pruning_boundary = journal.pruning_boundary();
    let mut rewind_size = journal_size;
    while rewind_size > pruning_boundary {
        let op = journal.read(rewind_size - 1).await?;
        if rewind_predicate(&op) {
            break;
        }
        rewind_size -= 1;
    }
    if rewind_size != journal_size {
        let rewound_ops = journal_size - rewind_size;
        warn!(journal_size, rewound_ops, "rewinding journal operations");
        journal.rewind(rewind_size).await?;
        journal.sync().await?;
    }

    Ok(rewind_size)
}

/// An append-only data structure that maintains a sequential journal of operations alongside a
/// Merkle Mountain Range (MMR). The operation at index i in the journal corresponds to the leaf at
/// Location i in the MMR. This structure enables efficient proofs that an operation is included in
/// the journal at a specific location.
// TODO(#2154): Expose Dirty and Clean variants of this type.
pub struct Journal<E, C, O, H>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item = O>,
    O: Encode,
    H: Hasher,
{
    /// MMR where each leaf is an operation digest.
    /// Invariant: leaf i corresponds to operation i in the journal.
    pub(crate) mmr: Mmr<E, H>,

    /// Journal of operations.
    /// Invariant: operation i corresponds to leaf i in the MMR.
    pub(crate) journal: C,

    pub(crate) hasher: StandardHasher<H>,
}

impl<E, C, O, H> Journal<E, C, O, H>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item = O>,
    O: Encode,
    H: Hasher,
{
    /// Align `mmr` to be consistent with `journal`.
    /// Any elements in `mmr` that aren't in `journal` are popped, and any elements in `journal`
    /// that aren't in `mmr` are added to `mmr`.
    async fn align(
        mut mmr: Mmr<E, H>,
        journal: &C,
        hasher: &mut StandardHasher<H>,
    ) -> Result<Mmr<E, H>, Error> {
        // Pop any MMR elements that are ahead of the journal.
        // Note mmr_size is the size of the MMR in leaves, not positions.
        let journal_size = journal.size();
        let mut mmr_size = mmr.leaves();
        if mmr_size > journal_size {
            let pop_count = mmr_size - journal_size;
            warn!(journal_size, ?pop_count, "popping MMR operations");
            mmr.pop(*pop_count as usize).await?;
            mmr_size = Location::new_unchecked(journal_size);
        }

        // If the MMR is behind, replay journal operations to catch up.
        if mmr_size < journal_size {
            let replay_count = journal_size - *mmr_size;
            warn!(
                journal_size,
                replay_count, "MMR lags behind journal, replaying journal to catch up"
            );

            let mut mmr = mmr.into_dirty();
            while mmr_size < journal_size {
                let op = journal.read(*mmr_size).await?;
                mmr.add_batched(hasher, &op.encode()).await?;
                mmr_size += 1;
            }
            let mut mmr = mmr.merkleize(hasher);
            mmr.sync().await?;
            return Ok(mmr);
        }

        // At this point the MMR and journal should be consistent.
        assert_eq!(journal.size(), mmr.leaves());

        Ok(mmr)
    }

    /// Append an operation.
    ///
    /// Returns the location where the operation was appended.
    pub async fn append(&mut self, op: O) -> Result<Location, Error> {
        let encoded_op = op.encode();

        // Append operation to the journal and update the MMR in parallel.
        let (_, loc) = try_join!(
            self.mmr
                .add(&mut self.hasher, &encoded_op)
                .map_err(Error::Mmr),
            self.journal.append(op).map_err(Into::into)
        )?;

        Ok(Location::new_unchecked(loc))
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

        // Sync the mmr before pruning the journal, otherwise the MMR tip could end up behind the journal's
        // pruning boundary on restart from an unclean shutdown, and there would be no way to replay
        // the operations between the MMR tip and the journal pruning boundary.
        self.mmr.sync().await?;

        // Prune the journal and check if anything was actually pruned
        if !self.journal.prune(*prune_loc).await? {
            return Ok(self.pruning_boundary());
        }

        let pruning_boundary = self.pruning_boundary();
        let op_count = self.op_count();
        debug!(
            ?op_count,
            ?prune_loc,
            ?pruning_boundary,
            "pruned inactive ops"
        );

        // Prune MMR to match the journal's actual boundary
        self.mmr
            .prune_to_pos(Position::try_from(pruning_boundary)?)
            .await?;

        Ok(pruning_boundary)
    }

    /// Generate a proof of inclusion for operations starting at `start_loc`.
    ///
    /// Returns a proof and the operations corresponding to the leaves in the range `start_loc..end_loc`,
    /// where `end_loc` is the minimum of the current operation count and `start_loc + max_ops`.
    ///
    /// # Errors
    ///
    /// - Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// - Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= current operation count.
    /// - Returns [Error::Journal] with [crate::journal::Error::ItemPruned] if `start_loc` has been pruned.
    pub async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<O>), Error> {
        self.historical_proof(self.op_count(), start_loc, max_ops)
            .await
    }

    /// Generate a historical proof with respect to the state of the MMR when it had `op_count`
    /// operations.
    ///
    /// Returns a proof and the operations corresponding to the leaves in the range `start_loc..end_loc`,
    /// where `end_loc` is the minimum of `op_count` and `start_loc + max_ops`.
    ///
    /// # Errors
    ///
    /// - Returns [crate::mmr::Error::LocationOverflow] if `op_count` or `start_loc` >
    ///   [crate::mmr::MAX_LOCATION].
    /// - Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= `op_count` or `op_count` >
    ///   number of operations in the journal.
    /// - Returns [Error::Journal] with [crate::journal::Error::ItemPruned] if `start_loc` has been pruned.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<O>), Error> {
        let size = Location::new_unchecked(self.journal.size());
        if op_count > size {
            return Err(crate::mmr::Error::RangeOutOfBounds(size).into());
        }
        if start_loc >= op_count {
            return Err(crate::mmr::Error::RangeOutOfBounds(start_loc).into());
        }
        let end_loc = std::cmp::min(op_count, start_loc.saturating_add(max_ops.get()));

        let mmr_size = Position::try_from(op_count)?;
        let proof = self
            .mmr
            .historical_range_proof(mmr_size, start_loc..end_loc)
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

    /// Get the current operation count (number of operations in the journal).
    pub fn op_count(&self) -> Location {
        self.mmr.leaves()
    }

    /// Read an operation from the journal at the given location.
    ///
    /// # Errors
    ///
    /// - Returns [crate::journal::Error::ItemPruned] if the operation at `loc` has been pruned.
    /// - Returns [crate::journal::Error::ItemOutOfRange] if the operation at `loc` does not exist.
    pub async fn read(&self, loc: Location) -> Result<O, Error> {
        self.journal.read(*loc).await.map_err(Error::Journal)
    }

    /// Return the root of the MMR.
    pub fn root(&mut self) -> H::Digest {
        self.mmr.root(&mut self.hasher)
    }

    /// Returns the oldest retained location in the journal.
    ///
    /// Returns `None` if the journal is empty or all items have been pruned.
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.journal
            .oldest_retained_pos()
            .map(Location::new_unchecked)
    }

    /// Returns the pruning boundary for the journal, which is the [Location] below which all
    /// operations have been pruned. If the returned location is the same as `op_count()`, then all
    /// operations have been pruned.
    pub fn pruning_boundary(&self) -> Location {
        self.journal.pruning_boundary().into()
    }

    /// Close the authenticated journal, syncing all pending writes.
    pub async fn close(self) -> Result<(), Error> {
        try_join!(
            self.journal.close().map_err(Error::Journal),
            self.mmr.close().map_err(Error::Mmr),
        )?;
        Ok(())
    }

    /// Destroy the authenticated journal, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        try_join!(
            self.journal.destroy().map_err(Error::Journal),
            self.mmr.destroy().map_err(Error::Mmr),
        )?;
        Ok(())
    }

    /// Replay operations from the journal starting at `start_loc`.
    ///
    /// Returns a stream of `(position, operation)` tuples. This is a thin wrapper
    /// around the journal's replay functionality.
    ///
    /// # Errors
    ///
    /// - Returns [crate::journal::Error::ItemPruned] if `start_loc` has been pruned.
    /// - Returns [crate::journal::Error::ItemOutOfRange] if `start_loc` > journal size.
    pub async fn replay(
        &self,
        start_loc: u64,
        buffer_size: NonZeroUsize,
    ) -> Result<
        impl futures::Stream<Item = Result<(u64, O), crate::journal::Error>> + '_,
        crate::journal::Error,
    > {
        self.journal.replay(start_loc, buffer_size).await
    }
}

impl<E, O, H> Journal<E, fixed::Journal<E, O>, O, H>
where
    E: Storage + Clock + Metrics,
    O: CodecFixed<Cfg = ()> + Encode,
    H: Hasher,
{
    /// Create a new [Journal] for fixed-length operations.
    ///
    /// The journal will be rewound to the last operation that matches the `rewind_predicate` on initialization.
    pub async fn new(
        context: E,
        mmr_cfg: crate::mmr::journaled::Config,
        journal_cfg: fixed::Config,
        rewind_predicate: fn(&O) -> bool,
    ) -> Result<Self, Error> {
        let mut hasher = StandardHasher::<H>::new();
        let mmr = Mmr::init(context.with_label("mmr"), &mut hasher, mmr_cfg).await?;
        let mut journal = fixed::Journal::init(context.with_label("journal"), journal_cfg).await?;

        // Rewind to last matching operation.
        rewind(&mut journal, rewind_predicate).await?;

        // Align the MMR and journal.
        let mmr = Self::align(mmr, &journal, &mut hasher).await?;
        Ok(Self {
            mmr,
            journal,
            hasher,
        })
    }

    /// Durably persist the journal. This is faster than `sync()` but does not persist the MMR,
    /// meaning recovery will be required on startup if we crash before `sync()` or `close()`.
    pub async fn sync_journal(&mut self) -> Result<(), Error> {
        self.journal.sync().await.map_err(Error::Journal)
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

impl<E, O, H> Journal<E, variable::Journal<E, O>, O, H>
where
    E: Storage + Clock + Metrics,
    O: Codec + Encode,
    H: Hasher,
{
    /// Create a new [Journal] for variable-length operations.
    ///
    /// The journal will be rewound to the last operation that matches the `rewind_predicate` on initialization.
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

        // Rewind to last matching operation.
        rewind(&mut journal, rewind_predicate).await?;

        // Align the MMR and journal.
        let mmr = Self::align(mmr, &journal, &mut hasher).await?;
        Ok(Self {
            mmr,
            journal,
            hasher,
        })
    }

    /// Durably persist the journal. This is faster than `sync()` but does not persist the MMR,
    /// meaning recovery will be required on startup if we crash before `sync()` or `close()`.
    pub async fn commit(&mut self) -> Result<(), Error> {
        self.journal.sync_data().await.map_err(Error::Journal)
    }

    /// Durably persist the data. This is slower than `commit()` but ensures recovery is not
    /// required on startup.
    pub async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.journal.sync().map_err(Error::Journal),
            self.mmr.sync().map_err(Into::into)
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb::operation::{fixed::unordered::Operation, Committable},
        journal::contiguous::fixed::{Config as JConfig, Journal as ContiguousJournal},
        mmr::{
            journaled::{Config as MmrConfig, Mmr},
            Location,
        },
    };
    use commonware_codec::Encode;
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::PoolRef,
        deterministic::{self, Context},
        Runner as _,
    };
    use commonware_utils::{NZUsize, NZU64};
    use futures::StreamExt as _;

    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    /// Create MMR configuration for tests.
    fn mmr_config(suffix: &str) -> MmrConfig {
        MmrConfig {
            journal_partition: format!("mmr_journal_{suffix}"),
            metadata_partition: format!("mmr_metadata_{suffix}"),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Create journal configuration for tests.
    fn journal_config(suffix: &str) -> JConfig {
        JConfig {
            partition: format!("journal_{suffix}"),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    /// Create a new empty authenticated journal.
    async fn create_empty_journal(
        context: Context,
        suffix: &str,
    ) -> Journal<
        deterministic::Context,
        ContiguousJournal<deterministic::Context, Operation<Digest, Digest>>,
        Operation<Digest, Digest>,
        Sha256,
    > {
        <Journal<
            deterministic::Context,
            ContiguousJournal<deterministic::Context, Operation<Digest, Digest>>,
            Operation<Digest, Digest>,
            Sha256,
        >>::new(
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
        Operation::Update(Sha256::fill(index), Sha256::fill(index.wrapping_add(1)))
    }

    /// Create an authenticated journal with N committed operations.
    ///
    /// Operations are added and then synced to ensure they are committed.
    async fn create_journal_with_ops(
        context: Context,
        suffix: &str,
        count: usize,
    ) -> Journal<
        deterministic::Context,
        ContiguousJournal<deterministic::Context, Operation<Digest, Digest>>,
        Operation<Digest, Digest>,
        Sha256,
    > {
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
        Mmr<deterministic::Context, Sha256>,
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

            assert_eq!(journal.op_count(), Location::new_unchecked(0));
        });
    }

    /// Verify that align() correctly handles empty MMR and journal components.
    #[test_traced("INFO")]
    fn test_align_with_empty_mmr_and_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, journal, mut hasher) = create_components(context, "align_empty").await;

            let mmr = Journal::align(mmr, &journal, &mut hasher).await.unwrap();

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
            let commit_op = Operation::CommitFloor(Location::new_unchecked(0));
            journal.append(commit_op).await.unwrap();
            journal.sync().await.unwrap();

            // MMR has 20 leaves, journal has 21 operations (20 ops + 1 commit)
            let mmr = Journal::align(mmr, &journal, &mut hasher).await.unwrap();

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
            let commit_op = Operation::CommitFloor(Location::new_unchecked(0));
            journal.append(commit_op).await.unwrap();
            journal.sync().await.unwrap();

            // Journal has 21 operations, MMR has 0 leaves
            mmr = Journal::align(mmr, &journal, &mut hasher).await.unwrap();

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
            let mut journal = create_empty_journal(context.clone(), "mismatched").await;

            // Add 20 uncommitted operations
            for i in 0..20 {
                let loc = journal.append(create_operation(i as u8)).await.unwrap();
                assert_eq!(loc, Location::new_unchecked(i as u64));
            }

            // Don't sync - these are uncommitted
            // After alignment, they should be discarded
            let op_count_before = journal.op_count();
            assert_eq!(op_count_before, Location::new_unchecked(20));

            // Close and recreate to simulate restart (which calls align internally)
            journal.close().await.unwrap();
            let journal = create_empty_journal(context, "mismatched").await;

            // Uncommitted operations should be gone
            assert_eq!(journal.op_count(), Location::new_unchecked(0));
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
                    .append(Operation::CommitFloor(Location::new_unchecked(0)))
                    .await
                    .unwrap();
                for i in 4..7 {
                    journal.append(create_operation(i)).await.unwrap();
                }

                // Rewind to last commit
                let final_size = rewind(&mut journal, |op| op.is_commit()).await.unwrap();
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
                    .append(Operation::CommitFloor(Location::new_unchecked(0)))
                    .await
                    .unwrap(); // pos 1
                journal.append(create_operation(2)).await.unwrap();
                journal
                    .append(Operation::CommitFloor(Location::new_unchecked(1)))
                    .await
                    .unwrap(); // pos 3
                journal.append(create_operation(4)).await.unwrap();

                // Should rewind to last commit (pos 3)
                let final_size = rewind(&mut journal, |op| op.is_commit()).await.unwrap();
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
                let final_size = rewind(&mut journal, |op| op.is_commit()).await.unwrap();
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
                    .append(Operation::CommitFloor(Location::new_unchecked(0)))
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
                let final_size = rewind(&mut journal, |op| op.is_commit()).await.unwrap();
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
                    .append(Operation::CommitFloor(Location::new_unchecked(0)))
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
                let final_size = rewind(&mut journal, |op| op.is_commit()).await.unwrap();
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
                let final_size = rewind(&mut journal, |op: &Operation<Digest, Digest>| {
                    op.is_commit()
                })
                .await
                .unwrap();
                assert_eq!(final_size, 0);
                assert_eq!(journal.size(), 0);
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

            assert_eq!(journal.op_count(), Location::new_unchecked(0));

            // Add 50 operations
            let expected_ops: Vec<_> = (0..50).map(|i| create_operation(i as u8)).collect();
            for (i, op) in expected_ops.iter().enumerate() {
                let loc = journal.append(op.clone()).await.unwrap();
                assert_eq!(loc, Location::new_unchecked(i as u64));
                assert_eq!(journal.op_count(), Location::new_unchecked((i + 1) as u64));
            }

            assert_eq!(journal.op_count(), Location::new_unchecked(50));

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
                .append(Operation::CommitFloor(Location::new_unchecked(50)))
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

    /// Verify that op_count() returns the correct number of operations.
    #[test_traced("INFO")]
    fn test_op_count_returns_correct_value() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "op_count", 50).await;

            assert_eq!(journal.op_count(), Location::new_unchecked(50));

            // Verify all operations can be read back and match expected values
            for i in 0..50 {
                let op = journal.read(Location::new_unchecked(i)).await.unwrap();
                assert_eq!(op, create_operation(i as u8));
            }
        });
    }

    /// Verify that close() syncs pending operations.
    #[test_traced("INFO")]
    fn test_close_with_pending_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_empty_journal(context.clone(), "close_pending").await;

            // Add 20 operations
            let expected_ops: Vec<_> = (0..20).map(|i| create_operation(i as u8)).collect();
            for (i, op) in expected_ops.iter().enumerate() {
                let loc = journal.append(op.clone()).await.unwrap();
                assert_eq!(loc, Location::new_unchecked(i as u64),);
            }

            // Add commit operation to commit the operations
            let commit_loc = journal
                .append(Operation::CommitFloor(Location::new_unchecked(0)))
                .await
                .unwrap();
            assert_eq!(
                commit_loc,
                Location::new_unchecked(20),
                "commit should be at location 20"
            );
            journal.close().await.unwrap();

            // Reopen and verify the operations persisted
            let journal = create_empty_journal(context, "close_pending").await;
            assert_eq!(journal.op_count(), Location::new_unchecked(21));

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
                .append(Operation::CommitFloor(Location::new_unchecked(50)))
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
                .append(Operation::CommitFloor(Location::new_unchecked(50)))
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
                .append(Operation::CommitFloor(Location::new_unchecked(50)))
                .await
                .unwrap();
            journal.sync().await.unwrap();

            let count_before = journal.op_count();
            journal.prune(Location::new_unchecked(50)).await.unwrap();
            let count_after = journal.op_count();

            assert_eq!(count_before, count_after);
        });
    }

    /// Verify oldest_retained_loc() for empty journal, no pruning, and after pruning.
    #[test_traced("INFO")]
    fn test_oldest_retained_loc() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Test empty journal
            let journal = create_empty_journal(context.clone(), "oldest").await;
            let oldest = journal.oldest_retained_loc();
            assert_eq!(oldest, None);

            // Test no pruning
            let journal = create_journal_with_ops(context.clone(), "oldest", 100).await;
            let oldest = journal.oldest_retained_loc();
            assert_eq!(oldest, Some(Location::new_unchecked(0)));

            // Test after pruning
            let mut journal = create_journal_with_ops(context, "oldest", 100).await;
            journal
                .append(Operation::CommitFloor(Location::new_unchecked(50)))
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
            let journal = create_empty_journal(context.clone(), "boundary").await;
            let boundary = journal.pruning_boundary();
            assert_eq!(boundary, Location::new_unchecked(0));

            // Test no pruning
            let journal = create_journal_with_ops(context.clone(), "boundary", 100).await;
            let boundary = journal.pruning_boundary();
            assert_eq!(boundary, Location::new_unchecked(0));

            // Test after pruning
            let mut journal = create_journal_with_ops(context, "boundary", 100).await;
            journal
                .append(Operation::CommitFloor(Location::new_unchecked(50)))
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
                .append(Operation::CommitFloor(Location::new_unchecked(25)))
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
            assert_eq!(journal.op_count(), Location::new_unchecked(51));
        });
    }

    /// Verify historical_proof() for multiple operations.
    #[test_traced("INFO")]
    fn test_historical_proof_multiple_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal = create_journal_with_ops(context, "proof_multi", 50).await;

            let op_count = journal.op_count();
            let (proof, ops) = journal
                .historical_proof(op_count, Location::new_unchecked(0), NZU64!(50))
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
            let mut journal = create_journal_with_ops(context, "proof_limit", 50).await;

            let op_count = journal.op_count();
            let (proof, ops) = journal
                .historical_proof(op_count, Location::new_unchecked(0), NZU64!(20))
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
            let mut journal = create_journal_with_ops(context, "proof_end", 50).await;

            let op_count = journal.op_count();
            // Request proof starting near the end
            let (proof, ops) = journal
                .historical_proof(op_count, Location::new_unchecked(40), NZU64!(20))
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

    /// Verify that historical_proof() returns an error for invalid op_count.
    #[test_traced("INFO")]
    fn test_historical_proof_out_of_range_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_oob", 5).await;

            // Request proof with op_count > actual journal size
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

    /// Verify that historical_proof() returns an error when start_loc >= op_count.
    #[test_traced("INFO")]
    fn test_historical_proof_start_too_large_returns_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let journal = create_journal_with_ops(context, "proof_start_oob", 5).await;

            let op_count = journal.op_count();
            // Request proof starting at op_count (should fail)
            let result = journal
                .historical_proof(op_count, op_count, NZU64!(1))
                .await;

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
            let historical_op_count = journal.op_count();

            // Add more operations after the historical state
            for i in 50..100 {
                journal.append(create_operation(i as u8)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Generate proof for the historical state
            let (proof, ops) = journal
                .historical_proof(historical_op_count, Location::new_unchecked(0), NZU64!(50))
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
                .append(Operation::CommitFloor(Location::new_unchecked(25)))
                .await
                .unwrap();
            journal.sync().await.unwrap();
            let pruned_boundary = journal.prune(Location::new_unchecked(25)).await.unwrap();

            // Try to get proof starting at a location before the pruned boundary
            let op_count = journal.op_count();
            let start_loc = Location::new_unchecked(0);
            if start_loc < pruned_boundary {
                let result = journal
                    .historical_proof(op_count, start_loc, NZU64!(1))
                    .await;

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
            let journal = create_empty_journal(context.clone(), "replay").await;
            let stream = journal.replay(0, NZUsize!(10)).await.unwrap();
            futures::pin_mut!(stream);
            assert!(stream.next().await.is_none());

            // Test replaying all operations
            let journal = create_journal_with_ops(context, "replay", 50).await;
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
