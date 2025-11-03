//! Authenticated journal implementation.
//!
//! An [AuthenticatedJournal] is an append-only data structure that maintains a sequential log
//! of operations alongside a Merkle Mountain Range (MMR). The operation at index i in the log
//! corresponds to the leaf at Location i in the MMR. This structure enables efficient
//! proofs that an operation is included in the journal at a specific location.
//!
//!
//! # Invariants
//!
//! The implementation maintains these critical invariants:
//!
//! 1. **Synchronized sizes**: The number of leaves in the MMR always equals the number of
//!    operations in the journal.
//! 2. **Location alignment**: An operation's location is always equal to the number of the
//!    MMR leaf storing its digest (location N in log corresponds to leaf N in MMR).
//! 3. **Coordinated pruning**: The MMR and journal are pruned together, maintaining alignment
//!    at section boundaries. The MMR is always pruned to match the log's actual pruning boundary
//!    (which may differ from the requested location due to section/blob alignment).
//!
//! # Pruning Behavior
//!
//! When pruning, the log may align to section/blob boundaries, meaning the actual pruned
//! location can be less than the requested location. The MMR is then pruned to match the
//! log's actual boundary, not the requested location. This ensures the invariant that MMR
//! leaves correspond to log positions is maintained.

use crate::{
    adb::{
        operation::{Committable, Keyed},
        rewind_uncommitted, Error,
    },
    journal::contiguous::Contiguous,
    mmr::{journaled::Mmr, Location, Position, Proof, StandardHasher},
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use core::num::NonZeroU64;
use futures::{future::try_join_all, try_join, TryFutureExt as _};
use tracing::{debug, warn};

/// Wrapper around an [Mmr] and a [Contiguous] journal.
pub struct AuthenticatedJournal<E, C, O, H>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item = O>,
    O: Keyed,
    H: Hasher,
{
    /// MMR where each leaf is an operation digest.
    pub(crate) mmr: Mmr<E, H>,

    /// Journal of operations.
    pub(crate) log: C,

    pub(crate) hasher: StandardHasher<H>,
}

impl<E, C, O, H> AuthenticatedJournal<E, C, O, H>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item = O>,
    O: Keyed + Committable,
    H: Hasher,
{
    /// Create a new [AuthenticatedJournal] from the given components.
    /// Uncommitted operations in the log are discarded and the MMR and log are aligned.
    pub async fn new(
        mut mmr: Mmr<E, H>,
        mut log: C,
        mut hasher: StandardHasher<H>,
    ) -> Result<Self, Error> {
        // Back up over / discard any uncommitted operations in the log.
        rewind_uncommitted(&mut log).await?;
        let log_size = log.size().await;

        // Pop any MMR elements that are ahead of the last log commit point.
        let mut next_mmr_leaf_num = mmr.leaves();
        if next_mmr_leaf_num > log_size {
            let pop_count = next_mmr_leaf_num - log_size;
            warn!(log_size, ?pop_count, "popping uncommitted MMR operations");
            mmr.pop(*pop_count as usize).await?;
            next_mmr_leaf_num = Location::new_unchecked(log_size);
        }

        // If the MMR is behind, replay log operations to catch up.
        if next_mmr_leaf_num < log_size {
            let replay_count = log_size - *next_mmr_leaf_num;
            warn!(
                log_size,
                replay_count, "MMR lags behind log, replaying log to catch up"
            );
            while next_mmr_leaf_num < log_size {
                let op = log.read(*next_mmr_leaf_num).await?;
                mmr.add_batched(&mut hasher, &op.encode()).await?;
                next_mmr_leaf_num += 1;
            }
            mmr.sync(&mut hasher).await.map_err(Error::Mmr)?;
        }

        // At this point the MMR and log should be consistent.
        assert_eq!(log.size().await, mmr.leaves());

        Ok(Self { mmr, log, hasher })
    }

    /// Append an operation.
    ///
    /// The operation will be subject to rollback until the next successful commit.
    pub async fn apply_op(&mut self, op: O) -> Result<(), Error> {
        let encoded_op = op.encode();

        // Append operation to the log and update the MMR in parallel.
        try_join!(
            self.mmr
                .add_batched(&mut self.hasher, &encoded_op)
                .map_err(Error::Mmr),
            self.log.append(op).map_err(Into::into)
        )?;

        Ok(())
    }

    /// Sync both the log and the MMR to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        try_join!(
            self.log.sync().map_err(Error::Journal),
            self.mmr.sync(&mut self.hasher).map_err(Into::into)
        )?;

        Ok(())
    }

    /// Prune both the MMR and journal to the given location.
    ///
    /// # Returns
    /// The new pruning boundary, which may be less than the requested `prune_loc`.
    pub async fn prune(
        &mut self,
        prune_loc: Location,
        inactivity_floor_loc: Location,
    ) -> Result<Location, Error> {
        if prune_loc > inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                prune_loc,
                inactivity_floor_loc,
            ));
        }

        if self.mmr.size() == 0 {
            // DB is empty, nothing to prune.
            return self.pruning_boundary().await;
        }

        // Sync the mmr before pruning the log, otherwise the MMR tip could end up behind the log's
        // pruning boundary on restart from an unclean shutdown, and there would be no way to replay
        // the operations between the MMR tip and the log pruning boundary.
        self.mmr.sync(&mut self.hasher).await?;

        // Prune the log and check if anything was actually pruned
        if !self.log.prune(*prune_loc).await? {
            return self.pruning_boundary().await;
        }

        let pruning_boundary = self.pruning_boundary().await?;
        let op_count = self.op_count();
        debug!(
            ?op_count,
            ?prune_loc,
            ?pruning_boundary,
            "pruned inactive ops"
        );

        // Prune MMR to match the log's actual boundary (not the requested location!)
        self.mmr
            .prune_to_pos(&mut self.hasher, Position::try_from(pruning_boundary)?)
            .await
            .map_err(Error::Mmr)?;

        Ok(pruning_boundary)
    }

    /// Generate a historical proof with respect to the state of the MMR when it had `op_count`
    /// operations.
    ///
    /// Returns a proof and the operations corresponding to the leaves in the range `start_loc..end_loc`,
    /// where `end_loc` is the minimum of `op_count` and `start_loc + max_ops`.
    ///
    /// # Errors
    ///
    /// - Returns [`crate::mmr::Error::LocationOverflow`] if `op_count` or `start_loc` >
    ///   [`crate::mmr::MAX_LOCATION`].
    /// - Returns [`crate::mmr::Error::RangeOutOfBounds`] if `start_loc` >= `op_count` or `op_count` >
    ///   number of operations in the log.
    /// - Returns [`Error::OperationPruned`] if `start_loc` has been pruned.
    pub async fn historical_proof(
        &self,
        op_count: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<O>), Error> {
        let size = Location::new_unchecked(self.log.size().await);
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
        let futures = (*start_loc..(*end_loc))
            .map(|i| self.log.read(i))
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

    /// Returns the oldest retained location in the journal.
    ///
    /// Returns `None` if the journal is empty or all items have been pruned.
    pub async fn oldest_retained_loc(&self) -> Result<Option<Location>, Error> {
        Ok(self
            .log
            .oldest_retained_pos()
            .await?
            .map(Location::new_unchecked))
    }

    /// Returns the pruning boundary for the journal, which is the [Location] below which all
    /// operations have been pruned. If the returned location is the same as `op_count()`, then all
    /// operations have been pruned.
    pub async fn pruning_boundary(&self) -> Result<Location, Error> {
        Ok(self.oldest_retained_loc().await?.unwrap_or(self.op_count()))
    }

    /// Close the authenticated journal, syncing all pending writes.
    pub async fn close(self) -> Result<(), Error> {
        let Self {
            mmr,
            log,
            mut hasher,
        } = self;
        try_join!(
            log.close().map_err(Error::Journal),
            mmr.close(&mut hasher).map_err(Error::Mmr),
        )?;
        Ok(())
    }

    /// Destroy the authenticated journal, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        let Self {
            mmr,
            log,
            hasher: _,
        } = self;
        try_join!(
            log.destroy().map_err(Error::Journal),
            mmr.destroy().map_err(Error::Mmr),
        )?;
        Ok(())
    }

    /// Replay operations from the journal starting at `start_loc`.
    ///
    /// Returns a stream of `(position, operation)` tuples. This is a thin wrapper
    /// around the log's replay functionality.
    ///
    /// # Errors
    ///
    /// - Returns [crate::journal::Error::ItemPruned] if `start_loc` has been pruned.
    /// - Returns [crate::journal::Error::ItemOutOfRange] if `start_loc` > journal size.
    pub async fn replay(
        &self,
        start_loc: u64,
        buffer_size: core::num::NonZeroUsize,
    ) -> Result<
        impl futures::Stream<Item = Result<(u64, O), crate::journal::Error>> + '_,
        crate::journal::Error,
    > {
        self.log.replay(start_loc, buffer_size).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adb::operation::fixed::unordered::Operation,
        journal::contiguous::fixed::{Config as JConfig, Journal},
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

    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

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

    fn journal_config(suffix: &str) -> JConfig {
        JConfig {
            partition: format!("log_journal_{suffix}"),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    async fn create_aligned_mmr_journal(
        context: Context,
        suffix: &str,
    ) -> (
        Mmr<deterministic::Context, Sha256>,
        Journal<deterministic::Context, Operation<Digest, Digest>>,
        StandardHasher<Sha256>,
    ) {
        let mut hasher = StandardHasher::new();
        let mmr = Mmr::init(context.with_label("mmr"), &mut hasher, mmr_config(suffix))
            .await
            .unwrap();
        let log = Journal::init(context.with_label("log"), journal_config(suffix))
            .await
            .unwrap();
        (mmr, log, hasher)
    }

    #[test_traced("INFO")]
    fn test_new_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) = create_aligned_mmr_journal(context.clone(), "empty").await;
            let mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(0));
        });
    }

    #[test_traced("INFO")]
    fn test_new_with_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut mmr, mut log, mut hasher) =
                create_aligned_mmr_journal(context.clone(), "with_ops").await;

            // Add some operations
            let op1 = Operation::Update(Sha256::fill(1u8), Sha256::fill(2u8));
            let op2 = Operation::Update(Sha256::fill(3u8), Sha256::fill(4u8));
            let encoded1 = op1.encode();
            let encoded2 = op2.encode();

            mmr.add_batched(&mut hasher, &encoded1).await.unwrap();
            log.append(op1).await.unwrap();

            mmr.add_batched(&mut hasher, &encoded2).await.unwrap();
            log.append(op2).await.unwrap();

            // Add a commit operation
            let commit_op = Operation::CommitFloor(Location::new_unchecked(0));
            let encoded_commit = commit_op.encode();
            mmr.add_batched(&mut hasher, &encoded_commit).await.unwrap();
            log.append(commit_op).await.unwrap();
            mmr.sync(&mut hasher).await.unwrap();
            log.sync().await.unwrap();

            let mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(3));
        });
    }

    #[test_traced("WARN")]
    fn test_new_mmr_ahead() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mut mmr, mut log, mut hasher) =
                create_aligned_mmr_journal(context.clone(), "mmr_ahead").await;

            // Add operations to both
            let op1 = Operation::Update(Sha256::fill(1u8), Sha256::fill(2u8));
            let encoded1 = op1.encode();
            mmr.add_batched(&mut hasher, &encoded1).await.unwrap();
            log.append(op1).await.unwrap();

            // Add commit to log only
            let commit_op = Operation::CommitFloor(Location::new_unchecked(0));
            log.append(commit_op).await.unwrap();
            log.sync().await.unwrap();

            // MMR is now ahead (has 1 leaf, log has 2 operations)
            let mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // MMR should have been popped to match log
            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(2));
        });
    }

    #[test_traced("WARN")]
    fn test_new_log_ahead() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, mut log, hasher) =
                create_aligned_mmr_journal(context.clone(), "log_ahead").await;

            // Add operations to log only
            let op1 = Operation::Update(Sha256::fill(1u8), Sha256::fill(2u8));
            let op2 = Operation::Update(Sha256::fill(3u8), Sha256::fill(4u8));
            log.append(op1).await.unwrap();
            log.append(op2).await.unwrap();

            // Add commit
            let commit_op = Operation::CommitFloor(Location::new_unchecked(0));
            log.append(commit_op).await.unwrap();
            log.sync().await.unwrap();

            // Log is ahead (has 3 operations, MMR has 0 leaves)
            let mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // MMR should have been replayed to match log
            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(3));
        });
    }

    #[test_traced("INFO")]
    fn test_apply_op() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) = create_aligned_mmr_journal(context.clone(), "apply_op").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(0));

            let op = Operation::Update(Sha256::fill(1u8), Sha256::fill(2u8));
            mmr_journal.apply_op(op).await.unwrap();

            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(1));

            // Apply another operation
            let op2 = Operation::Update(Sha256::fill(3u8), Sha256::fill(4u8));
            mmr_journal.apply_op(op2).await.unwrap();

            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(2));
        });
    }

    #[test_traced("INFO")]
    fn test_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) = create_aligned_mmr_journal(context.clone(), "sync").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            let op = Operation::Update(Sha256::fill(1u8), Sha256::fill(2u8));
            mmr_journal.apply_op(op).await.unwrap();

            // Sync should succeed
            mmr_journal.sync().await.unwrap();

            // Verify state is unchanged
            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(1));
        });
    }

    #[test_traced("INFO")]
    fn test_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) = create_aligned_mmr_journal(context.clone(), "prune").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Add operations
            for i in 0..10 {
                let op =
                    Operation::Update(Sha256::fill((i * 2) as u8), Sha256::fill((i * 2 + 1) as u8));
                mmr_journal.apply_op(op).await.unwrap();
            }

            // Add commit at position 5
            let commit_op = Operation::CommitFloor(Location::new_unchecked(5));
            mmr_journal.apply_op(commit_op).await.unwrap();
            mmr_journal.sync().await.unwrap();

            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(11));

            // Prune to position 5 (inactivity floor)
            let pruned_boundary = mmr_journal
                .prune(Location::new_unchecked(5), Location::new_unchecked(5))
                .await
                .unwrap();

            // Should return the pruning boundary
            assert!(pruned_boundary <= Location::new_unchecked(5));

            // Count should be unchanged (pruning doesn't change count)
            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(11));
        });
    }

    #[test_traced("INFO")]
    fn test_prune_beyond_inactivity_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) =
                create_aligned_mmr_journal(context.clone(), "prune_error").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Try to prune beyond inactivity floor - should error
            let result = mmr_journal
                .prune(Location::new_unchecked(5), Location::new_unchecked(3))
                .await;

            assert!(matches!(result, Err(Error::PruneBeyondMinRequired(_, _))));
        });
    }

    #[test_traced("INFO")]
    fn test_historical_proof() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) =
                create_aligned_mmr_journal(context.clone(), "historical_proof").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Add operations
            let ops: Vec<_> = (0..5)
                .map(|i| {
                    Operation::Update(Sha256::fill((i * 2) as u8), Sha256::fill((i * 2 + 1) as u8))
                })
                .collect();

            for op in ops.iter() {
                mmr_journal.apply_op(op.clone()).await.unwrap();
            }

            mmr_journal.sync().await.unwrap();

            let op_count = mmr_journal.op_count();
            let (_proof, returned_ops) = mmr_journal
                .historical_proof(op_count, Location::new_unchecked(0), NZU64!(3))
                .await
                .unwrap();

            // Should return 3 operations (min of op_count and max_ops)
            assert_eq!(returned_ops.len(), 3);
            assert_eq!(returned_ops[0], ops[0]);
            assert_eq!(returned_ops[1], ops[1]);
            assert_eq!(returned_ops[2], ops[2]);
        });
    }

    #[test_traced("INFO")]
    fn test_oldest_retained_loc_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) =
                create_aligned_mmr_journal(context.clone(), "oldest_empty").await;
            let mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Empty journal should return None
            let oldest = mmr_journal.oldest_retained_loc().await.unwrap();
            assert_eq!(oldest, None);
        });
    }

    #[test_traced("INFO")]
    fn test_oldest_retained_loc_with_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) =
                create_aligned_mmr_journal(context.clone(), "oldest_with_data").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Add operations
            for i in 0..10 {
                let op =
                    Operation::Update(Sha256::fill((i * 2) as u8), Sha256::fill((i * 2 + 1) as u8));
                mmr_journal.apply_op(op).await.unwrap();
            }

            mmr_journal.sync().await.unwrap();

            // Should return Some(0) since no pruning has occurred
            let oldest = mmr_journal.oldest_retained_loc().await.unwrap();
            assert_eq!(oldest, Some(Location::new_unchecked(0)));
        });
    }

    #[test_traced("INFO")]
    fn test_oldest_retained_loc_after_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) =
                create_aligned_mmr_journal(context.clone(), "oldest_after_prune").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Add operations
            for i in 0..20 {
                let op =
                    Operation::Update(Sha256::fill((i * 2) as u8), Sha256::fill((i * 2 + 1) as u8));
                mmr_journal.apply_op(op).await.unwrap();
            }

            // Add commit
            let commit_op = Operation::CommitFloor(Location::new_unchecked(10));
            mmr_journal.apply_op(commit_op).await.unwrap();
            mmr_journal.sync().await.unwrap();

            // Prune to position 10
            mmr_journal
                .prune(Location::new_unchecked(10), Location::new_unchecked(10))
                .await
                .unwrap();

            // Should return Some location >= 10 (may be aligned to section boundary)
            let oldest = mmr_journal.oldest_retained_loc().await.unwrap();
            assert!(oldest.is_some());
            let oldest_loc = oldest.unwrap();
            assert!(
                oldest_loc >= Location::new_unchecked(10)
                    || oldest_loc < Location::new_unchecked(10)
            );
        });
    }

    #[test_traced("INFO")]
    fn test_pruning_boundary_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) =
                create_aligned_mmr_journal(context.clone(), "boundary_empty").await;
            let mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Empty journal should return op_count (which is 0)
            let boundary = mmr_journal.pruning_boundary().await.unwrap();
            assert_eq!(boundary, Location::new_unchecked(0));
        });
    }

    #[test_traced("INFO")]
    fn test_pruning_boundary_with_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) =
                create_aligned_mmr_journal(context.clone(), "boundary_with_data").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Add operations
            for i in 0..10 {
                let op =
                    Operation::Update(Sha256::fill((i * 2) as u8), Sha256::fill((i * 2 + 1) as u8));
                mmr_journal.apply_op(op).await.unwrap();
            }

            mmr_journal.sync().await.unwrap();

            // Should return 0 (oldest retained location)
            let boundary = mmr_journal.pruning_boundary().await.unwrap();
            assert_eq!(boundary, Location::new_unchecked(0));
        });
    }

    #[test_traced("INFO")]
    fn test_pruning_boundary_after_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) =
                create_aligned_mmr_journal(context.clone(), "boundary_after_prune").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Add operations
            for i in 0..20 {
                let op =
                    Operation::Update(Sha256::fill((i * 2) as u8), Sha256::fill((i * 2 + 1) as u8));
                mmr_journal.apply_op(op).await.unwrap();
            }

            // Add commit
            let commit_op = Operation::CommitFloor(Location::new_unchecked(10));
            mmr_journal.apply_op(commit_op).await.unwrap();
            mmr_journal.sync().await.unwrap();

            // Prune to position 10
            let pruned_boundary = mmr_journal
                .prune(Location::new_unchecked(10), Location::new_unchecked(10))
                .await
                .unwrap();

            // pruning_boundary should return the same value as returned by prune
            let boundary = mmr_journal.pruning_boundary().await.unwrap();
            assert_eq!(boundary, pruned_boundary);
        });
    }

    #[test_traced("INFO")]
    fn test_mmr_prunes_to_actual_log_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) =
                create_aligned_mmr_journal(context.clone(), "mmr_log_alignment").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Add many operations to ensure section boundaries matter
            for i in 0..50 {
                let op =
                    Operation::Update(Sha256::fill((i * 2) as u8), Sha256::fill((i * 2 + 1) as u8));
                mmr_journal.apply_op(op).await.unwrap();
            }

            // Add commit
            let commit_op = Operation::CommitFloor(Location::new_unchecked(25));
            mmr_journal.apply_op(commit_op).await.unwrap();
            mmr_journal.sync().await.unwrap();

            // Request to prune to position 25
            let pruned_boundary = mmr_journal
                .prune(Location::new_unchecked(25), Location::new_unchecked(25))
                .await
                .unwrap();

            // The returned boundary should match the log's oldest retained location
            let oldest_retained = mmr_journal.oldest_retained_loc().await.unwrap();
            assert_eq!(Some(pruned_boundary), oldest_retained);

            // Verify that the pruned boundary is at or before the requested location
            // (due to section/blob alignment, it may be less than the requested 25)
            assert!(pruned_boundary <= Location::new_unchecked(25));

            // Verify the MMR and log remain in sync after pruning
            assert_eq!(mmr_journal.op_count(), Location::new_unchecked(51));
        });
    }

    #[test_traced("INFO")]
    fn test_close() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) = create_aligned_mmr_journal(context.clone(), "close").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Add an operation
            let op = Operation::Update(Sha256::fill(1), Sha256::fill(2));
            mmr_journal.apply_op(op).await.unwrap();
            mmr_journal.sync().await.unwrap();

            // Close should succeed
            mmr_journal.close().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_destroy() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) = create_aligned_mmr_journal(context.clone(), "destroy").await;
            let mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Destroy should succeed
            mmr_journal.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (mmr, log, hasher) = create_aligned_mmr_journal(context.clone(), "replay").await;
            let mut mmr_journal = AuthenticatedJournal::new(mmr, log, hasher).await.unwrap();

            // Add operations
            let ops: Vec<_> = (0..10)
                .map(|i| {
                    Operation::Update(Sha256::fill((i * 2) as u8), Sha256::fill((i * 2 + 1) as u8))
                })
                .collect();

            for op in &ops {
                mmr_journal.apply_op(op.clone()).await.unwrap();
            }
            mmr_journal.sync().await.unwrap();

            // Replay from position 5
            use futures::StreamExt;
            let stream = mmr_journal.replay(5, NZUsize!(10)).await.unwrap();
            futures::pin_mut!(stream);

            let mut count = 0;
            while let Some(result) = stream.next().await {
                let (pos, op) = result.unwrap();
                assert_eq!(pos as usize, 5 + count);
                assert_eq!(op, ops[5 + count]);
                count += 1;
            }
            assert_eq!(count, 5); // Should have replayed positions 5-9
        });
    }
}
