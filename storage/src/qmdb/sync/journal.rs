use crate::{
    journal::contiguous::{Contiguous, Many},
    merkle::{Family, Location},
};
use commonware_utils::range::NonEmptyRange;
use std::future::Future;

/// Journal of operations used by a [super::Database]
pub trait Journal<F: Family>: Sized + Send {
    /// The context of the journal
    type Context;

    /// The configuration of the journal
    type Config: Sync;

    /// The type of operations in the journal
    type Op: Send + Sync;

    /// The error type returned by the journal
    type Error: std::error::Error + Send + 'static + Into<crate::qmdb::Error<F>>;

    /// Create/open a journal for syncing the given range.
    ///
    /// The implementation must:
    /// - Reuse any on-disk data whose logical locations lie within the range.
    /// - Discard/ignore any data outside the range.
    /// - Report `size()` equal to the next location to be filled.
    fn new(
        context: Self::Context,
        config: Self::Config,
        range: NonEmptyRange<Location<F>>,
    ) -> impl Future<Output = Result<Self, Self::Error>> + Send;

    /// Discard all operations before the given location.
    ///
    /// If current `size() <= start`, initialize as empty at the given location.
    /// Otherwise prune data before the given location.
    fn resize(self, start: Location<F>) -> impl Future<Output = Result<Self, Self::Error>> + Send;

    /// Persist the journal.
    fn sync(self) -> impl Future<Output = Result<Self, Self::Error>> + Send;

    /// The size of the journal, including pruned operations.
    fn size(&self) -> u64;

    /// Append a non-empty batch of operations.
    fn append(self, ops: Vec<Self::Op>) -> impl Future<Output = Result<Self, Self::Error>> + Send;
}

impl<F, E, V> Journal<F> for crate::journal::contiguous::variable::Journal<E, V>
where
    F: Family,
    E: crate::Context,
    V: commonware_codec::CodecShared,
{
    type Context = E;
    type Config = crate::journal::contiguous::variable::Config<V::Cfg>;
    type Op = V;
    type Error = crate::journal::Error;

    async fn new(
        context: Self::Context,
        config: Self::Config,
        range: NonEmptyRange<Location<F>>,
    ) -> Result<Self, Self::Error> {
        crate::journal::authenticated::init_sync(context, config, *range.start()..*range.end())
            .await
    }

    async fn resize(self, start: Location<F>) -> Result<Self, Self::Error> {
        if Contiguous::bounds(&self).end <= *start {
            self.clear_to_size(*start).await
        } else {
            let (journal, _) = self.prune(*start).await?;
            Ok(journal)
        }
    }

    async fn sync(self) -> Result<Self, Self::Error> {
        Self::sync(self).await
    }

    fn size(&self) -> u64 {
        Contiguous::bounds(self).end
    }

    async fn append(self, ops: Vec<Self::Op>) -> Result<Self, Self::Error> {
        let (journal, _) = self.append_many(Many::Flat(&ops)).await?;
        Ok(journal)
    }
}

impl<F, E, A> Journal<F> for crate::journal::contiguous::fixed::Journal<E, A>
where
    F: Family,
    E: crate::Context,
    A: commonware_codec::CodecFixedShared,
{
    type Context = E;
    type Config = crate::journal::contiguous::fixed::Config;
    type Op = A;
    type Error = crate::journal::Error;

    async fn new(
        context: Self::Context,
        config: Self::Config,
        range: NonEmptyRange<Location<F>>,
    ) -> Result<Self, Self::Error> {
        crate::journal::authenticated::init_sync(context, config, *range.start()..*range.end())
            .await
    }

    async fn resize(self, start: Location<F>) -> Result<Self, Self::Error> {
        if Contiguous::bounds(&self).end <= *start {
            self.clear_to_size(*start).await
        } else {
            let (journal, _) = self.prune(*start).await?;
            Ok(journal)
        }
    }

    async fn sync(self) -> Result<Self, Self::Error> {
        Self::sync(self).await
    }

    fn size(&self) -> u64 {
        Contiguous::bounds(self).end
    }

    async fn append(self, ops: Vec<Self::Op>) -> Result<Self, Self::Error> {
        let (journal, _) = self.append_many(Many::Flat(&ops)).await?;
        Ok(journal)
    }
}

/// An in-memory operation journal.
pub struct Memory<F: Family, E, Op> {
    start: Location<F>,
    ops: Vec<Op>,
    _context: std::marker::PhantomData<fn() -> E>,
}

impl<F: Family, E, Op> Memory<F, E, Op> {
    /// Consume the journal, returning its start location and operations.
    pub(crate) fn into_parts(self) -> (Location<F>, Vec<Op>) {
        (self.start, self.ops)
    }
}

impl<F, E, Op> Journal<F> for Memory<F, E, Op>
where
    F: Family,
    E: Send,
    Op: Send + Sync,
{
    type Context = E;
    type Config = ();
    type Op = Op;
    type Error = crate::qmdb::Error<F>;

    async fn new(
        _context: Self::Context,
        _config: Self::Config,
        range: NonEmptyRange<Location<F>>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            start: range.start(),
            ops: Vec::new(),
            _context: std::marker::PhantomData,
        })
    }

    async fn resize(mut self, start: Location<F>) -> Result<Self, Self::Error> {
        if start < self.start || *start >= self.size() {
            self.start = start;
            self.ops.clear();
        } else {
            self.ops.drain(..(*start - *self.start) as usize);
            self.start = start;
        }
        Ok(self)
    }

    async fn sync(self) -> Result<Self, Self::Error> {
        Ok(self)
    }

    fn size(&self) -> u64 {
        *self.start + self.ops.len() as u64
    }

    async fn append(mut self, ops: Vec<Self::Op>) -> Result<Self, Self::Error> {
        self.ops.extend(ops);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::{fixed, variable};
    use commonware_cryptography::sha256::Digest;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Blob, BufferPooler, Runner, Storage, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, SyncFaultContext, drive_pending_syncs},
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};

    type FixedJournal = fixed::Journal<deterministic::Context, Digest>;
    type VariableJournal = variable::Journal<deterministic::Context, u64>;
    type F = crate::merkle::mmr::Family;

    fn test_cfg(pooler: &impl BufferPooler) -> fixed::Config {
        fixed::Config {
            partition: "sync-journal-test".into(),
            items_per_blob: NZU64!(5),
            page_cache: CacheRef::from_pooler(pooler, NZU16!(44), NZUsize!(3)),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
        }
    }

    fn variable_test_cfg(pooler: &impl BufferPooler) -> variable::Config<()> {
        variable::Config {
            partition: "variable-sync-journal-test".into(),
            items_per_section: NZU64!(5),
            compression: None,
            codec_config: (),
            write_buffer: NZUsize!(2048),
            replay_buffer: NZUsize!(2048),
            page_cache: CacheRef::from_pooler(pooler, NZU16!(44), NZUsize!(3)),
        }
    }

    #[test_traced]
    fn test_memory_journal() {
        type Mem = Memory<F, (), u64>;
        deterministic::Runner::default().start(|_context| async move {
            let range = non_empty_range!(Location::new(10), Location::new(20));

            // A fresh journal is empty at the range start.
            let journal = <Mem as Journal<F>>::new((), (), range.clone())
                .await
                .unwrap();
            assert_eq!(journal.size(), 10);

            // Appends extend the size.
            let journal = journal.append(vec![1, 2, 3]).await.unwrap();
            assert_eq!(journal.size(), 13);

            // A resize within the retained ops drains the prefix.
            let journal = journal.resize(Location::new(12)).await.unwrap();
            assert_eq!(journal.size(), 13);
            let (start, ops) = journal.into_parts();
            assert_eq!(start, Location::new(12));
            assert_eq!(ops, vec![3]);

            // A resize at or beyond the size clears to an empty journal at the new start.
            let journal = <Mem as Journal<F>>::new((), (), range.clone())
                .await
                .unwrap();
            let journal = journal.append(vec![1, 2]).await.unwrap();
            let journal = journal.resize(Location::new(15)).await.unwrap();
            assert_eq!(journal.size(), 15);
            let (start, ops) = journal.into_parts();
            assert_eq!(start, Location::new(15));
            assert!(ops.is_empty());

            // A resize before the start clears.
            let journal = <Mem as Journal<F>>::new((), (), range).await.unwrap();
            let journal = journal.append(vec![1]).await.unwrap();
            let journal = journal.resize(Location::new(5)).await.unwrap();
            assert_eq!(journal.size(), 5);
            let (start, ops) = journal.into_parts();
            assert_eq!(start, Location::new(5));
            assert!(ops.is_empty());
        });
    }

    #[test_traced]
    fn test_sync_journal_new_recovers_from_stale_clear_to_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create a journal at pruning_boundary=9 (mid-section in section 1).
            let journal = FixedJournal::init_at_size(context.child("setup"), cfg.clone(), 9)
                .await
                .unwrap();
            let journal = journal.sync().await.unwrap();
            drop(journal);

            // Simulate clear_to_size(7) crash: blobs cleared, section 1 recreated
            // empty, but metadata still says pruning_boundary=9.
            let blob_part = format!("{}-blobs", cfg.partition);
            context.remove(&blob_part, None).await.unwrap();
            let (blob, _) = context.open(&blob_part, &1u64.to_be_bytes()).await.unwrap();
            blob.sync().await.unwrap();
            drop(blob);

            // Reopening must restore the requested start so locations 7-8 are not skipped.
            let range = non_empty_range!(
                crate::merkle::Location::<F>::new(7),
                crate::merkle::Location::<F>::new(20)
            );
            let journal = <FixedJournal as Journal<F>>::new(context.child("sync"), cfg, range)
                .await
                .unwrap();

            let size = Contiguous::bounds(&journal).end;
            assert_eq!(size, 7);
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 7);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sync_journal_new_stale_empty_position_beyond_range_end() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Create a journal at pruning_boundary=30, well beyond our intended range end.
            let journal = FixedJournal::init_at_size(context.child("setup"), cfg.clone(), 30)
                .await
                .unwrap();
            let journal = journal.sync().await.unwrap();
            drop(journal);

            // No operations exist to retain, so opening resets to the requested start.
            let range = non_empty_range!(
                crate::merkle::Location::<F>::new(7),
                crate::merkle::Location::<F>::new(20)
            );
            let journal = <FixedJournal as Journal<F>>::new(context.child("sync"), cfg, range)
                .await
                .unwrap();

            let size = Contiguous::bounds(&journal).end;
            assert_eq!(size, 7);
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 7);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_sync_journal_preserves_metric_prefix() {
        for reset in [false, true] {
            deterministic::Runner::default().start(|context| async move {
                let cfg = test_cfg(&context);
                if reset {
                    let journal =
                        FixedJournal::init_at_size(context.child("seed"), cfg.clone(), 30)
                            .await
                            .unwrap();
                    _ = journal.sync().await.unwrap();
                }
                let start = if reset { 7 } else { 0 };
                let range = non_empty_range!(Location::<F>::new(start), Location::new(20));
                let journal = <FixedJournal as Journal<F>>::new(context.child("sync"), cfg, range)
                    .await
                    .unwrap();
                assert_eq!(journal.bounds(), start..start);
                let metrics = commonware_runtime::Metrics::encode(&context);
                let expected = format!("sync_size {start}");
                assert!(metrics.lines().any(|line| line == expected), "{metrics}");
                assert!(!metrics.contains("sync_journal_"), "{metrics}");
            });
        }
    }

    #[test_traced]
    fn test_fixed_sync_journal_caps_ahead_and_discards_pruned_progress() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = FixedJournal::init(context.child("setup"), cfg.clone())
                .await
                .unwrap();
            for value in 0..30u8 {
                (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
            }
            let journal = journal.sync().await.unwrap();
            drop(journal);

            let range = non_empty_range!(Location::<F>::new(7), Location::<F>::new(20));
            let journal =
                <FixedJournal as Journal<F>>::new(context.child("sync"), cfg.clone(), range)
                    .await
                    .unwrap();

            assert_eq!(journal.bounds(), 5..20);
            for value in 7..20u8 {
                assert_eq!(
                    journal.read(value.into()).await.unwrap(),
                    Digest([value; 32])
                );
            }
            journal.destroy().await.unwrap();

            let mut journal = FixedJournal::init(context.child("pruned_setup"), cfg.clone())
                .await
                .unwrap();
            for value in 0..50u8 {
                (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
            }
            let journal = <FixedJournal as Journal<F>>::resize(journal, Location::new(40))
                .await
                .unwrap();
            let journal = journal.sync().await.unwrap();
            assert!(journal.bounds().start > 7);
            drop(journal);

            let range = non_empty_range!(Location::<F>::new(7), Location::<F>::new(60));
            let journal =
                <FixedJournal as Journal<F>>::new(context.child("pruned_sync"), cfg, range)
                    .await
                    .unwrap();

            assert_eq!(journal.bounds(), 7..7);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_sync_journal_preserves_metric_prefix() {
        for reset in [false, true] {
            deterministic::Runner::default().start(|context| async move {
                let cfg = variable_test_cfg(&context);
                if reset {
                    let journal =
                        VariableJournal::init_at_size(context.child("seed"), cfg.clone(), 30)
                            .await
                            .unwrap();
                    _ = journal.sync().await.unwrap();
                }
                let start = if reset { 7 } else { 0 };
                let range = non_empty_range!(Location::<F>::new(start), Location::new(20));
                let journal =
                    <VariableJournal as Journal<F>>::new(context.child("sync"), cfg, range)
                        .await
                        .unwrap();
                assert_eq!(journal.bounds(), start..start);
                let metrics = commonware_runtime::Metrics::encode(&context);
                let expected = format!("sync_size {start}");
                assert!(metrics.lines().any(|line| line == expected), "{metrics}");
                assert!(!metrics.contains("sync_journal_"), "{metrics}");
            });
        }
    }

    #[test_traced]
    fn test_variable_sync_journal_caps_ahead_and_discards_pruned_progress() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = variable_test_cfg(&context);
            let mut journal = VariableJournal::init(context.child("setup"), cfg.clone())
                .await
                .unwrap();
            for value in 0..30u64 {
                (journal, _) = journal.append(&value).await.unwrap();
            }
            let journal = journal.sync().await.unwrap();
            drop(journal);

            let range = non_empty_range!(Location::<F>::new(7), Location::<F>::new(20));
            let journal =
                <VariableJournal as Journal<F>>::new(context.child("sync"), cfg.clone(), range)
                    .await
                    .unwrap();

            assert_eq!(journal.bounds(), 5..20);
            for value in 7..20u64 {
                assert_eq!(journal.read(value).await.unwrap(), value);
            }
            journal.destroy().await.unwrap();

            let mut journal = VariableJournal::init(context.child("pruned_setup"), cfg.clone())
                .await
                .unwrap();
            for value in 0..50u64 {
                (journal, _) = journal.append(&value).await.unwrap();
            }
            let journal = <VariableJournal as Journal<F>>::resize(journal, Location::new(40))
                .await
                .unwrap();
            let journal = journal.sync().await.unwrap();
            assert!(journal.bounds().start > 7);
            drop(journal);

            let range = non_empty_range!(Location::<F>::new(7), Location::<F>::new(60));
            let journal =
                <VariableJournal as Journal<F>>::new(context.child("pruned_sync"), cfg, range)
                    .await
                    .unwrap();

            assert_eq!(journal.bounds(), 7..7);
            journal.destroy().await.unwrap();
        });
    }

    /// Tear the tail page of `blob` so its next open must repair it.
    async fn tear(context: &deterministic::Context, partition: &str, blob: u64) {
        let (blob, len) = context.open(partition, &blob.to_be_bytes()).await.unwrap();
        blob.resize(len - 1).await.unwrap();
        blob.sync().await.unwrap();
    }

    #[test]
    fn test_fixed_sync_journal_empty_at_start_reopens_without_reset() {
        deterministic::Runner::default().start(|context| async move {
            let cfg = test_cfg(&context);
            let range = non_empty_range!(Location::<F>::new(7), Location::<F>::new(20));
            let mut calls = Vec::new();
            for attempt in ["first", "second"] {
                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: context.child(attempt),
                    pending: pending.clone(),
                };
                let journal = drive_pending_syncs(
                    &pending,
                    <fixed::Journal<_, Digest> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg.clone(),
                        range.clone(),
                    ),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 7..7);
                calls.push(pending.calls());
                drop(journal);
            }

            // The first open resets an empty journal to the range start. The second finds it
            // already there and publishes it without staging another reset.
            assert!(calls[1] < calls[0], "{calls:?}");
        });
    }

    #[test_traced]
    fn test_fixed_sync_journal_reset_leaves_pruned_blobs_unopened() {
        deterministic::Runner::default().start(|context| async move {
            let mut calls = Vec::new();
            for torn in [false, true] {
                let context = context.child(if torn { "torn" } else { "clean" });
                let mut cfg = test_cfg(&context);
                cfg.partition = format!("sync-journal-{torn}");
                let mut journal = FixedJournal::init(context.child("setup"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..50u8 {
                    (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
                }
                let journal = <FixedJournal as Journal<F>>::resize(journal, Location::new(40))
                    .await
                    .unwrap();
                let journal = journal.sync().await.unwrap();
                assert!(journal.bounds().start > 20);
                drop(journal);
                if torn {
                    tear(&context, &format!("{}-blobs", cfg.partition), 9).await;
                }

                let reopen = context.child("reopen");
                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: context,
                    pending: pending.clone(),
                };
                let range = non_empty_range!(Location::<F>::new(7), Location::<F>::new(20));
                let mut journal = drive_pending_syncs(
                    &pending,
                    <fixed::Journal<_, Digest> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg.clone(),
                        range,
                    ),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 7..7);
                calls.push(pending.calls());

                // The cleared journal accepts appends that survive an ordinary reopen.
                for value in 7..10u8 {
                    (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
                }
                let journal = drive_pending_syncs(&pending, journal.sync()).await.unwrap();
                drop(journal);
                let journal = FixedJournal::init(reopen, cfg).await.unwrap();
                assert_eq!(journal.bounds(), 7..10);
                for value in 7..10u8 {
                    assert_eq!(
                        journal.read(value as u64).await.unwrap(),
                        Digest([value; 32])
                    );
                }
                journal.destroy().await.unwrap();
            }

            // Every retained blob lies beyond the range, so the reset must not open any of them:
            // a torn tail costs no repair.
            assert_eq!(calls[0], calls[1]);
        });
    }

    #[test_traced]
    fn test_fixed_sync_journal_repairs_retained_torn_tail() {
        deterministic::Runner::default().start(|context| async move {
            let mut calls = Vec::new();
            for torn in [false, true] {
                let context = context.child(if torn { "torn" } else { "clean" });
                let mut cfg = test_cfg(&context);
                cfg.partition = format!("sync-journal-{torn}");
                let mut journal = FixedJournal::init(context.child("setup"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..30u8 {
                    (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
                }
                // Commit leaves the watermark behind the data, so the tail is unacknowledged.
                let journal = journal.commit().await.unwrap();
                drop(journal);
                if torn {
                    tear(&context, &format!("{}-blobs", cfg.partition), 5).await;
                }

                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: context,
                    pending: pending.clone(),
                };
                let range = non_empty_range!(Location::<F>::new(7), Location::<F>::new(30));
                let journal = drive_pending_syncs(
                    &pending,
                    <fixed::Journal<_, Digest> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg,
                        range,
                    ),
                )
                .await
                .unwrap();
                let bounds = journal.bounds();
                assert_eq!(bounds.start, 5);
                if torn {
                    assert!(bounds.end < 30);
                } else {
                    assert_eq!(bounds.end, 30);
                }
                for value in 7..bounds.end {
                    assert_eq!(
                        journal.read(value).await.unwrap(),
                        Digest([value as u8; 32])
                    );
                }
                calls.push(pending.calls());
                journal.destroy().await.unwrap();
            }

            // A torn tail inside the range is repaired.
            assert!(calls[1] > calls[0]);
        });
    }

    #[test_traced]
    fn test_variable_sync_journal_reset_leaves_pruned_blobs_unopened() {
        deterministic::Runner::default().start(|context| async move {
            let mut calls = Vec::new();
            for torn in [false, true] {
                let context = context.child(if torn { "torn" } else { "clean" });
                let mut cfg = variable_test_cfg(&context);
                cfg.partition = format!("variable-sync-journal-{torn}");
                let data = format!("{}_data", cfg.partition);
                let mut journal = VariableJournal::init(context.child("setup"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..50u64 {
                    (journal, _) = journal.append(&value).await.unwrap();
                }
                let journal = <VariableJournal as Journal<F>>::resize(journal, Location::new(40))
                    .await
                    .unwrap();
                let journal = journal.sync().await.unwrap();
                assert!(journal.bounds().start > 20);
                drop(journal);
                if torn {
                    tear(&context, &data, 9).await;
                }

                // Discarded data is never synced, so a sync fault on its partition is unreachable.
                let reopen = context.child("reopen");
                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: SyncFaultContext {
                        inner: context,
                        fail_partition: data,
                    },
                    pending: pending.clone(),
                };
                let range = non_empty_range!(Location::<F>::new(7), Location::<F>::new(20));
                let journal = drive_pending_syncs(
                    &pending,
                    Box::pin(<variable::Journal<_, u64> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg.clone(),
                        range,
                    )),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 7..7);
                calls.push(pending.calls());
                drop(journal);

                // The cleared journal accepts appends that survive an ordinary reopen. Appends
                // sync the data partition, so they run outside the faulting context.
                let mut journal = VariableJournal::init(reopen.child("append"), cfg.clone())
                    .await
                    .unwrap();
                assert_eq!(journal.bounds(), 7..7);
                for value in 7..10u64 {
                    (journal, _) = journal.append(&value).await.unwrap();
                }
                let journal = journal.sync().await.unwrap();
                drop(journal);
                let journal = VariableJournal::init(reopen, cfg).await.unwrap();
                assert_eq!(journal.bounds(), 7..10);
                for value in 7..10u64 {
                    assert_eq!(journal.read(value).await.unwrap(), value);
                }
                journal.destroy().await.unwrap();
            }

            // Every retained blob lies beyond the range, so the reset must not open any of them:
            // a torn tail costs no repair.
            assert_eq!(calls[0], calls[1]);
        });
    }

    #[test_traced]
    fn test_variable_sync_journal_repairs_retained_torn_tail() {
        deterministic::Runner::default().start(|context| async move {
            let mut calls = Vec::new();
            for torn in [false, true] {
                let context = context.child(if torn { "torn" } else { "clean" });
                let mut cfg = variable_test_cfg(&context);
                cfg.partition = format!("variable-sync-journal-{torn}");
                let mut journal = VariableJournal::init(context.child("setup"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..30u64 {
                    (journal, _) = journal.append(&value).await.unwrap();
                }
                // Commit leaves the watermark behind the data, so the tail is unacknowledged.
                let journal = journal.commit().await.unwrap();
                drop(journal);
                if torn {
                    tear(&context, &format!("{}_data", cfg.partition), 5).await;
                }

                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: context,
                    pending: pending.clone(),
                };
                let range = non_empty_range!(Location::<F>::new(7), Location::<F>::new(30));
                let journal = drive_pending_syncs(
                    &pending,
                    Box::pin(<variable::Journal<_, u64> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg,
                        range,
                    )),
                )
                .await
                .unwrap();
                let bounds = journal.bounds();
                assert_eq!(bounds.start, 5);
                if torn {
                    assert!(bounds.end < 30);
                } else {
                    assert_eq!(bounds.end, 30);
                }
                for value in 7..bounds.end {
                    assert_eq!(journal.read(value).await.unwrap(), value);
                }
                calls.push(pending.calls());
                journal.destroy().await.unwrap();
            }

            // A torn tail inside the range is repaired.
            assert!(calls[1] > calls[0]);
        });
    }

    #[test_traced]
    fn test_fixed_sync_journal_start_below_retained_leaves_blobs_unopened() {
        deterministic::Runner::default().start(|context| async move {
            let mut calls = Vec::new();
            for torn in [false, true] {
                let context = context.child(if torn { "torn" } else { "clean" });
                let mut cfg = test_cfg(&context);
                cfg.partition = format!("sync-journal-{torn}");
                let mut journal = FixedJournal::init(context.child("setup"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..50u8 {
                    (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
                }
                // Pruning syncs the retained blobs without advancing the recovery watermark, so
                // a torn tail is a crash shape rather than corruption.
                let journal = <FixedJournal as Journal<F>>::resize(journal, Location::new(40))
                    .await
                    .unwrap();
                assert_eq!(journal.bounds(), 40..50);
                drop(journal);
                if torn {
                    tear(&context, &format!("{}-blobs", cfg.partition), 9).await;
                }

                let reopen = context.child("reopen");
                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: context,
                    pending: pending.clone(),
                };
                let range = non_empty_range!(Location::<F>::new(20), Location::<F>::new(60));
                let mut journal = drive_pending_syncs(
                    &pending,
                    <fixed::Journal<_, Digest> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg.clone(),
                        range,
                    ),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 20..20);
                calls.push(pending.calls());

                // The cleared journal accepts appends that survive an ordinary reopen.
                for value in 20..23u8 {
                    (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
                }
                let journal = drive_pending_syncs(&pending, journal.sync()).await.unwrap();
                drop(journal);
                let journal = FixedJournal::init(reopen, cfg).await.unwrap();
                assert_eq!(journal.bounds(), 20..23);
                for value in 20..23u8 {
                    assert_eq!(
                        journal.read(value as u64).await.unwrap(),
                        Digest([value; 32])
                    );
                }
                journal.destroy().await.unwrap();
            }

            // The retained start lies inside the range, so the journal cannot serve it and is
            // reset without opening any blob: a torn tail costs no repair.
            assert_eq!(calls[0], calls[1]);
        });
    }

    #[test_traced]
    fn test_fixed_sync_journal_stale_below_start_leaves_blobs_unopened() {
        deterministic::Runner::default().start(|context| async move {
            let mut calls = Vec::new();
            for torn in [false, true] {
                let context = context.child(if torn { "torn" } else { "clean" });
                let mut cfg = test_cfg(&context);
                cfg.partition = format!("sync-journal-{torn}");
                let mut journal = FixedJournal::init(context.child("setup"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..30u8 {
                    (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
                }
                // Commit leaves the watermark behind the data, so the tail is unacknowledged.
                let journal = journal.commit().await.unwrap();
                drop(journal);
                if torn {
                    tear(&context, &format!("{}-blobs", cfg.partition), 5).await;
                }

                let reopen = context.child("reopen");
                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: context,
                    pending: pending.clone(),
                };
                let range = non_empty_range!(Location::<F>::new(50), Location::<F>::new(70));
                let mut journal = drive_pending_syncs(
                    &pending,
                    <fixed::Journal<_, Digest> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg.clone(),
                        range,
                    ),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 50..50);
                calls.push(pending.calls());

                // The cleared journal accepts appends that survive an ordinary reopen.
                for value in 50..53u8 {
                    (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
                }
                let journal = drive_pending_syncs(&pending, journal.sync()).await.unwrap();
                drop(journal);
                let journal = FixedJournal::init(reopen, cfg).await.unwrap();
                assert_eq!(journal.bounds(), 50..53);
                for value in 50..53u8 {
                    assert_eq!(
                        journal.read(value as u64).await.unwrap(),
                        Digest([value; 32])
                    );
                }
                journal.destroy().await.unwrap();
            }

            // Every stored item lies below the range start, so the journal is reset without
            // opening any blob: a torn tail costs no repair.
            assert_eq!(calls[0], calls[1]);
        });
    }

    #[test_traced]
    fn test_fixed_sync_journal_start_inside_newest_blob_opens_it() {
        deterministic::Runner::default().start(|context| async move {
            let mut calls = Vec::new();
            for torn in [false, true] {
                let context = context.child(if torn { "torn" } else { "clean" });
                let mut cfg = test_cfg(&context);
                cfg.partition = format!("sync-journal-{torn}");
                let mut journal = FixedJournal::init(context.child("setup"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..27u8 {
                    (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
                }
                // Commit leaves the watermark behind the data, so the tail is unacknowledged.
                let journal = journal.commit().await.unwrap();
                drop(journal);
                if torn {
                    tear(&context, &format!("{}-blobs", cfg.partition), 5).await;
                }

                let reopen = context.child("reopen");
                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: context,
                    pending: pending.clone(),
                };
                let range = non_empty_range!(Location::<F>::new(28), Location::<F>::new(40));
                let mut journal = drive_pending_syncs(
                    &pending,
                    <fixed::Journal<_, Digest> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg.clone(),
                        range,
                    ),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 28..28);
                calls.push(pending.calls());

                // The cleared journal accepts appends that survive an ordinary reopen.
                for value in 28..31u8 {
                    (journal, _) = journal.append(&Digest([value; 32])).await.unwrap();
                }
                let journal = drive_pending_syncs(&pending, journal.sync()).await.unwrap();
                drop(journal);
                let journal = FixedJournal::init(reopen, cfg).await.unwrap();
                assert_eq!(journal.bounds(), 28..31);
                for value in 28..31u8 {
                    assert_eq!(
                        journal.read(value as u64).await.unwrap(),
                        Digest([value; 32])
                    );
                }
                journal.destroy().await.unwrap();
            }

            // The range starts inside the newest blob, whose capacity reaches past it. Only its
            // recovered size shows that no item reaches the range, so that blob is opened and a
            // torn tail there is repaired before the reset.
            assert!(calls[1] > calls[0]);
        });
    }

    #[test_traced]
    fn test_variable_sync_journal_start_below_retained_leaves_blobs_unopened() {
        deterministic::Runner::default().start(|context| async move {
            let mut calls = Vec::new();
            for torn in [false, true] {
                let context = context.child(if torn { "torn" } else { "clean" });
                let mut cfg = variable_test_cfg(&context);
                cfg.partition = format!("variable-sync-journal-{torn}");
                let data = format!("{}_data", cfg.partition);
                let mut journal = VariableJournal::init(context.child("setup"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..50u64 {
                    (journal, _) = journal.append(&value).await.unwrap();
                }
                // Pruning syncs the retained blobs without advancing the recovery watermark, so
                // a torn tail is a crash shape rather than corruption.
                let journal = <VariableJournal as Journal<F>>::resize(journal, Location::new(40))
                    .await
                    .unwrap();
                assert_eq!(journal.bounds(), 40..50);
                drop(journal);
                if torn {
                    tear(&context, &data, 9).await;
                }

                // Discarded data is never synced, so a sync fault on its partition is unreachable.
                let reopen = context.child("reopen");
                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: SyncFaultContext {
                        inner: context,
                        fail_partition: data,
                    },
                    pending: pending.clone(),
                };
                let range = non_empty_range!(Location::<F>::new(20), Location::<F>::new(60));
                let journal = drive_pending_syncs(
                    &pending,
                    Box::pin(<variable::Journal<_, u64> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg.clone(),
                        range,
                    )),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 20..20);
                calls.push(pending.calls());
                drop(journal);

                // The cleared journal accepts appends that survive an ordinary reopen. Appends
                // sync the data partition, so they run outside the faulting context.
                let mut journal = VariableJournal::init(reopen.child("append"), cfg.clone())
                    .await
                    .unwrap();
                assert_eq!(journal.bounds(), 20..20);
                for value in 20..23u64 {
                    (journal, _) = journal.append(&value).await.unwrap();
                }
                let journal = journal.sync().await.unwrap();
                drop(journal);
                let journal = VariableJournal::init(reopen, cfg).await.unwrap();
                assert_eq!(journal.bounds(), 20..23);
                for value in 20..23u64 {
                    assert_eq!(journal.read(value).await.unwrap(), value);
                }
                journal.destroy().await.unwrap();
            }

            // The retained start lies inside the range, so the journal cannot serve it and is
            // reset without opening any blob: a torn tail costs no repair.
            assert_eq!(calls[0], calls[1]);
        });
    }

    #[test_traced]
    fn test_variable_sync_journal_stale_below_start_leaves_blobs_unopened() {
        deterministic::Runner::default().start(|context| async move {
            let mut calls = Vec::new();
            for torn in [false, true] {
                let context = context.child(if torn { "torn" } else { "clean" });
                let mut cfg = variable_test_cfg(&context);
                cfg.partition = format!("variable-sync-journal-{torn}");
                let data = format!("{}_data", cfg.partition);
                let mut journal = VariableJournal::init(context.child("setup"), cfg.clone())
                    .await
                    .unwrap();
                for value in 0..30u64 {
                    (journal, _) = journal.append(&value).await.unwrap();
                }
                // Commit leaves the watermark behind the data, so the tail is unacknowledged.
                let journal = journal.commit().await.unwrap();
                drop(journal);
                if torn {
                    tear(&context, &data, 5).await;
                }

                // Discarded data is never synced, so a sync fault on its partition is unreachable.
                let reopen = context.child("reopen");
                let pending = PendingSyncs::default();
                pending.arm();
                let delayed = DelayedSyncContext {
                    inner: SyncFaultContext {
                        inner: context,
                        fail_partition: data,
                    },
                    pending: pending.clone(),
                };
                let range = non_empty_range!(Location::<F>::new(50), Location::<F>::new(70));
                let journal = drive_pending_syncs(
                    &pending,
                    Box::pin(<variable::Journal<_, u64> as Journal<F>>::new(
                        delayed.child("sync"),
                        cfg.clone(),
                        range,
                    )),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 50..50);
                calls.push(pending.calls());
                drop(journal);

                // The cleared journal accepts appends that survive an ordinary reopen. Appends
                // sync the data partition, so they run outside the faulting context.
                let mut journal = VariableJournal::init(reopen.child("append"), cfg.clone())
                    .await
                    .unwrap();
                assert_eq!(journal.bounds(), 50..50);
                for value in 50..53u64 {
                    (journal, _) = journal.append(&value).await.unwrap();
                }
                let journal = journal.sync().await.unwrap();
                drop(journal);
                let journal = VariableJournal::init(reopen, cfg).await.unwrap();
                assert_eq!(journal.bounds(), 50..53);
                for value in 50..53u64 {
                    assert_eq!(journal.read(value).await.unwrap(), value);
                }
                journal.destroy().await.unwrap();
            }

            // Every stored item lies below the range start, so the journal is reset without
            // opening any blob: a torn tail costs no repair.
            assert_eq!(calls[0], calls[1]);
        });
    }
}
