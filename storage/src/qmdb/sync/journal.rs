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

    /// Get the number of operations in the journal
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

        // After a crash during a previous clear_to_size, the journal may recover empty at a stale
        // position ahead of the requested start (possibly even beyond range.end). Re-clear so the
        // sync engine starts from the correct location.
        let bounds = journal.bounds();
        if bounds.is_empty() && bounds.start > *range.start() {
            return journal.clear_to_size(*range.start()).await;
        }

        if size > *range.end() {
            return Err(crate::journal::Error::ItemOutOfRange(size));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::fixed;
    use commonware_cryptography::sha256::Digest;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Blob, BufferPooler, Runner, Storage, Supervisor as _, buffer::paged::CacheRef,
        deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range};

    type FixedJournal = fixed::Journal<deterministic::Context, Digest>;
    type F = crate::merkle::mmr::Family;

    fn test_cfg(pooler: &impl BufferPooler) -> fixed::Config {
        fixed::Config {
            partition: "sync-journal-test".into(),
            items_per_blob: NZU64!(5),
            page_cache: CacheRef::from_pooler(pooler, NZU16!(44), NZUsize!(3)),
            write_buffer: NZUsize!(2048),
        }
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

            // Without the fix, this reopens at 9..9 and the sync engine skips
            // locations 7-8. With the fix, it re-clears to 7.
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

            // Open via Journal::new with a range whose end < 30. Without the fix this would
            // return ItemOutOfRange because size(30) > range.end(20).
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
}
