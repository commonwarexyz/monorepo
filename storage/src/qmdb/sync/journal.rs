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
    fn append(self, ops: &[Self::Op]) -> impl Future<Output = Result<Self, Self::Error>> + Send;
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
        Self::init_sync(context, config.clone(), *range.start()..*range.end()).await
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

    async fn append(self, ops: &[Self::Op]) -> Result<Self, Self::Error> {
        let (journal, _) = self.append_many(Many::Flat(ops)).await?;
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
        let mut journal = Self::init(context, config).await?;
        let size = Contiguous::bounds(&journal).end;

        // Fresh journal already aligned with the sync start - nothing to do.
        if size == 0 && *range.start() == 0 {
            return Ok(journal);
        }

        // A pruned start cannot be reconstructed from the retained suffix.
        let bounds = journal.bounds();
        if bounds.start > *range.start() {
            return journal.clear_to_size(*range.start()).await;
        }

        // Sync targets describe the same append-only log, so progress beyond an older target can
        // retain its authenticated prefix instead of refetching it.
        if size > *range.end() {
            journal = journal.rewind(*range.end()).await?;
        }

        if size <= *range.start() {
            journal = journal.clear_to_size(*range.start()).await?;
        } else {
            (journal, _) = journal.prune(*range.start()).await?;
        }

        Ok(journal)
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

    async fn append(self, ops: &[Self::Op]) -> Result<Self, Self::Error> {
        let (journal, _) = self.append_many(Many::Flat(ops)).await?;
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
    Op: Clone + Send + Sync,
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

    async fn append(mut self, ops: &[Self::Op]) -> Result<Self, Self::Error> {
        self.ops.extend_from_slice(ops);
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
        Blob, BufferPooler, Runner, Storage, Supervisor as _, buffer::paged::CacheRef,
        deterministic,
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
            let journal = journal.append(&[1, 2, 3]).await.unwrap();
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
            let journal = journal.append(&[1, 2]).await.unwrap();
            let journal = journal.resize(Location::new(15)).await.unwrap();
            assert_eq!(journal.size(), 15);
            let (start, ops) = journal.into_parts();
            assert_eq!(start, Location::new(15));
            assert!(ops.is_empty());

            // A resize before the start clears.
            let journal = <Mem as Journal<F>>::new((), (), range).await.unwrap();
            let journal = journal.append(&[1]).await.unwrap();
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

            // No operations exist to rewind, so opening resets to the requested start.
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
    fn test_fixed_sync_journal_new_rewinds_ahead_and_discards_pruned_progress() {
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
    fn test_variable_sync_journal_new_rewinds_ahead_and_discards_pruned_progress() {
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
}
