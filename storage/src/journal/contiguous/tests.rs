//! Generic test suite for [Contiguous] trait implementations.

use super::{fixed, variable, Contiguous, Many, Reader as _};
use crate::journal::{authenticated, contiguous::Mutable, Error};
use commonware_macros::boxed;
use commonware_utils::NZUsize;
use futures::{future::BoxFuture, FutureExt, StreamExt};
use std::sync::atomic::{AtomicUsize, Ordering};

trait JournalHarness: Send + 'static {
    type Writer: Mutable<Item = u64>;
    type Readers: Contiguous<Item = u64>;

    fn split(self) -> (Self::Writer, Self::Readers);
    async fn rewind(writer: &mut Self::Writer, size: u64) -> Result<(), Error>;
    async fn destroy(writer: Self::Writer) -> Result<(), Error>;
}

impl<E: crate::Context> JournalHarness for fixed::Journal<E, u64> {
    type Writer = fixed::Writer<E, u64>;
    type Readers = fixed::Readers<E, u64>;

    fn split(self) -> (Self::Writer, Self::Readers) {
        Self::split(self)
    }

    async fn rewind(writer: &mut Self::Writer, size: u64) -> Result<(), Error> {
        writer.rewind(size).await
    }

    async fn destroy(writer: Self::Writer) -> Result<(), Error> {
        <Self as authenticated::Inner<E>>::destroy(writer).await
    }
}

impl<E: crate::Context> JournalHarness for variable::Journal<E, u64> {
    type Writer = variable::Writer<E, u64>;
    type Readers = variable::Readers<E, u64>;

    fn split(self) -> (Self::Writer, Self::Readers) {
        Self::split(self)
    }

    async fn rewind(writer: &mut Self::Writer, size: u64) -> Result<(), Error> {
        writer.rewind(size).await
    }

    async fn destroy(writer: Self::Writer) -> Result<(), Error> {
        <Self as authenticated::Inner<E>>::destroy(writer).await
    }
}

pub(super) trait TestSplitJournal: Mutable<Item = u64> + Contiguous<Item = u64> {
    async fn rewind(&mut self, size: u64) -> Result<(), Error>;
    async fn destroy(self) -> Result<(), Error>
    where
        Self: Sized;
}

struct SplitJournal<J: JournalHarness> {
    writer: J::Writer,
    readers: J::Readers,
}

impl<J: JournalHarness> SplitJournal<J> {
    fn new(journal: J) -> Self {
        let (writer, readers) = journal.split();
        Self { writer, readers }
    }
}

impl<J: JournalHarness> Mutable for SplitJournal<J> {
    type Item = u64;

    async fn size(&self) -> u64 {
        self.writer.size().await
    }

    async fn append(&mut self, item: &Self::Item) -> Result<u64, Error> {
        self.writer.append(item).await
    }

    async fn append_many<'a>(&'a mut self, items: Many<'a, Self::Item>) -> Result<u64, Error>
    where
        Self::Item: Sync,
    {
        self.writer.append_many(items).await
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        self.writer.prune(min_position).await
    }

    async fn commit(&mut self) -> Result<(), Error> {
        self.writer.commit().await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.writer.sync().await
    }
}

impl<J: JournalHarness> Contiguous for SplitJournal<J> {
    type Item = u64;

    async fn reader(&self) -> impl super::Reader<Item = Self::Item> + '_ {
        self.readers.reader().await
    }

    async fn size(&self) -> u64 {
        self.readers.size().await
    }
}

impl<J: JournalHarness> TestSplitJournal for SplitJournal<J> {
    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        J::rewind(&mut self.writer, size).await
    }

    async fn destroy(self) -> Result<(), Error> {
        let Self { writer, readers } = self;
        drop(readers);
        J::destroy(writer).await
    }
}

pub(super) mod partition_sync_fault {
    use commonware_runtime::{
        deterministic, telemetry::metrics, Blob, Clock, Error, IoBufs, IoBufsMut, Metrics, Name,
        Storage, Supervisor,
    };
    use governor::clock::{Clock as GovernorClock, ReasonablyRealtime};
    use std::{
        future::Future,
        io::Error as IoError,
        ops::RangeInclusive,
        time::{Duration, SystemTime},
    };

    pub(in crate::journal::contiguous) struct Context {
        inner: deterministic::Context,
        fail_partition: String,
    }

    impl Context {
        pub(in crate::journal::contiguous) fn new(
            inner: deterministic::Context,
            fail_partition: String,
        ) -> Self {
            Self {
                inner,
                fail_partition,
            }
        }
    }

    #[derive(Clone)]
    pub(in crate::journal::contiguous) struct BlobWithSyncFault<B: Blob> {
        inner: B,
        partition: String,
        fail_partition: String,
    }

    impl Supervisor for Context {
        fn name(&self) -> Name {
            self.inner.name()
        }

        fn child(&self, label: &'static str) -> Self {
            Self {
                inner: self.inner.child(label),
                fail_partition: self.fail_partition.clone(),
            }
        }

        fn with_attribute(mut self, key: &'static str, value: impl std::fmt::Display) -> Self {
            self.inner = self.inner.with_attribute(key, value);
            self
        }
    }

    impl Metrics for Context {
        fn register<N: Into<String>, H: Into<String>, M: metrics::Metric>(
            &self,
            name: N,
            help: H,
            metric: M,
        ) -> metrics::Registered<M> {
            self.inner.register(name, help, metric)
        }

        fn encode(&self) -> String {
            self.inner.encode()
        }
    }

    impl Clock for Context {
        fn current(&self) -> SystemTime {
            self.inner.current()
        }

        fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static {
            self.inner.sleep(duration)
        }

        fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static {
            self.inner.sleep_until(deadline)
        }
    }

    impl GovernorClock for Context {
        type Instant = SystemTime;

        fn now(&self) -> Self::Instant {
            self.current()
        }
    }

    impl ReasonablyRealtime for Context {}

    impl Storage for Context {
        type Blob = BlobWithSyncFault<<deterministic::Context as Storage>::Blob>;

        async fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: RangeInclusive<u16>,
        ) -> Result<(Self::Blob, u64, u16), Error> {
            let (inner, len, version) =
                self.inner.open_versioned(partition, name, versions).await?;
            Ok((
                BlobWithSyncFault {
                    inner,
                    partition: partition.to_string(),
                    fail_partition: self.fail_partition.clone(),
                },
                len,
                version,
            ))
        }

        async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), Error> {
            self.inner.remove(partition, name).await
        }

        async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
            self.inner.scan(partition).await
        }
    }

    impl<B: Blob> Blob for BlobWithSyncFault<B> {
        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
            self.inner.read_at(offset, len).await
        }

        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            self.inner.read_at_buf(offset, len, bufs).await
        }

        async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
            self.inner.write_at(offset, bufs).await
        }

        async fn write_at_sync(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), Error> {
            self.inner.write_at_sync(offset, bufs).await
        }

        async fn resize(&self, len: u64) -> Result<(), Error> {
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), Error> {
            if self.partition == self.fail_partition {
                return Err(Error::Io(IoError::other("injected partition sync fault")));
            }
            self.inner.sync().await
        }
    }
}

async fn get_bounds<J: Contiguous>(journal: &J) -> std::ops::Range<u64> {
    let reader = journal.reader().await;
    reader.bounds()
}

async fn read_item<J: Contiguous>(journal: &J, position: u64) -> Result<J::Item, Error> {
    let reader = journal.reader().await;
    reader.read(position).await
}

/// Run the full suite of generic tests on a [Contiguous] implementation.
///
/// The factory function receives a test identifier string and a unique index
/// for each invocation. Use both to create unique contexts/partitions to avoid
/// metric name collisions (the deterministic runtime panics on duplicate metrics).
///
/// # Assumptions
///
/// These tests assume the journal is configured with **`items_per_blob = 10`**.
/// Some tests rely on this value for blob-boundary calculations and pruning behavior.
#[boxed]
pub(super) async fn run_contiguous_tests<F, J>(factory: F)
where
    F: Fn(String, usize) -> BoxFuture<'static, Result<J, Error>>,
    J: JournalHarness,
{
    let counter = AtomicUsize::new(0);
    let indexed_factory = |name: String| {
        let idx = counter.fetch_add(1, Ordering::SeqCst);
        let future = factory(name, idx);
        async move { future.await.map(SplitJournal::new) }.boxed()
    };

    test_empty_journal_bounds(&indexed_factory).await;
    test_bounds_with_items(&indexed_factory).await;
    test_bounds_after_prune(&indexed_factory).await;
    test_append_and_size(&indexed_factory).await;
    test_sequential_appends(&indexed_factory).await;
    test_replay_from_start(&indexed_factory).await;
    test_replay_from_middle(&indexed_factory).await;
    test_prune_retains_size(&indexed_factory).await;
    test_through_trait(&indexed_factory).await;
    test_replay_after_prune(&indexed_factory).await;
    test_prune_then_append(&indexed_factory).await;
    test_position_stability(&indexed_factory).await;
    test_sync_behavior(&indexed_factory).await;
    test_replay_on_empty(&indexed_factory).await;
    test_replay_at_exact_size(&indexed_factory).await;
    test_multiple_prunes(&indexed_factory).await;
    test_prune_beyond_size(&indexed_factory).await;
    test_persistence_basic(&indexed_factory).await;
    test_persistence_after_prune(&indexed_factory).await;
    test_read_by_position(&indexed_factory).await;
    test_read_many(&indexed_factory).await;
    test_read_out_of_range(&indexed_factory).await;
    test_read_after_prune(&indexed_factory).await;
    test_section_boundary_behavior(&indexed_factory).await;
    test_destroy_and_reinit(&indexed_factory).await;
    test_append_many_empty(&indexed_factory).await;
    test_append_many_basic(&indexed_factory).await;
    test_append_many_across_sections(&indexed_factory).await;
    test_append_many_then_append(&indexed_factory).await;
    test_append_many_single_item(&indexed_factory).await;
    test_split_rewind_refused_while_readers_factory_alive(&indexed_factory).await;
}

/// Test that an empty journal has empty bounds (start == end == 0).
async fn test_empty_journal_bounds<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let journal = factory("empty".into()).await.unwrap();
    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, 0);
    assert!(bounds.is_empty());
    journal.destroy().await.unwrap();
}

/// Test that bounds returns 0..size for journal with items.
async fn test_bounds_with_items<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("bounds-with-items".into()).await.unwrap();

    // Append some items
    for i in 0..10 {
        journal.append(&(i * 100)).await.unwrap();
    }

    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, 10);
    assert!(!bounds.is_empty());
    journal.destroy().await.unwrap();
}

/// Test that bounds updates after pruning.
///
/// This test assumes items_per_blob = 10.
async fn test_bounds_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("bounds-after-prune".into()).await.unwrap();

    // Append items across multiple sections
    for i in 0..30 {
        journal.append(&(i * 100)).await.unwrap();
    }

    // Initially bounds should be 0..30
    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, 30);

    // Prune first section - trait only guarantees section-aligned pruning
    journal.prune(10).await.unwrap();

    // Assumed blob-aligned pruning and items_per_blob = 10.
    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.start, 10);
    assert_eq!(bounds.end, 30);

    // Prune more
    journal.prune(25).await.unwrap();

    // bounds.start should have advanced to 20 (section-aligned)
    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.start, 20);
    assert_eq!(bounds.end, 30);

    // Prune all
    journal.prune(30).await.unwrap();
    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.start, 30);
    assert_eq!(bounds.end, 30);
    assert!(bounds.is_empty());

    // Drop and reopen
    journal.sync().await.unwrap();
    drop(journal);
    let journal = factory("bounds-after-prune".into()).await.unwrap();
    let bounds = get_bounds(&journal).await;
    assert!(bounds.is_empty());
    journal.destroy().await.unwrap();
}

/// Test that append returns sequential positions and size increments.
async fn test_append_and_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("append-and-size".into()).await.unwrap();

    let pos1 = journal.append(&100).await.unwrap();
    let pos2 = journal.append(&200).await.unwrap();
    let pos3 = journal.append(&300).await.unwrap();

    assert_eq!(pos1, 0);
    assert_eq!(pos2, 1);
    assert_eq!(pos3, 2);
    assert_eq!(get_bounds(&journal).await.end, 3);

    // Verify values can be read back
    assert_eq!(read_item(&journal, 0).await.unwrap(), 100);
    assert_eq!(read_item(&journal, 1).await.unwrap(), 200);
    assert_eq!(read_item(&journal, 2).await.unwrap(), 300);

    journal.destroy().await.unwrap();
}

/// Test appending many items across section boundaries.
async fn test_sequential_appends<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("sequential-appends".into()).await.unwrap();

    for i in 0..25u64 {
        let pos = journal.append(&(i * 10)).await.unwrap();
        assert_eq!(pos, i);
    }

    assert_eq!(get_bounds(&journal).await.end, 25);

    for i in 0..25u64 {
        assert_eq!(read_item(&journal, i).await.unwrap(), i * 10);
    }

    journal.destroy().await.unwrap();
}

/// Test replay from the start of the journal.
async fn test_replay_from_start<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("replay-from-start".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&(i * 10)).await.unwrap();
    }

    {
        let reader = journal.reader().await;
        let stream = reader.replay(NZUsize!(1024), 0).await.unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 10);
        for (i, (pos, value)) in items.iter().enumerate() {
            assert_eq!(*pos, i as u64);
            assert_eq!(*value, (i as u64) * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test replay from the middle of the journal.
async fn test_replay_from_middle<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("replay-from-middle".into()).await.unwrap();

    for i in 0..15u64 {
        journal.append(&(i * 10)).await.unwrap();
    }

    {
        let reader = journal.reader().await;
        let stream = reader.replay(NZUsize!(1024), 7).await.unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 8);
        for (i, (pos, value)) in items.iter().enumerate() {
            assert_eq!(*pos, (i + 7) as u64);
            assert_eq!(*value, ((i + 7) as u64) * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test that size is unchanged after pruning.
async fn test_prune_retains_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("prune-retains-size".into()).await.unwrap();

    for i in 0..20u64 {
        journal.append(&i).await.unwrap();
    }

    let size_before = get_bounds(&journal).await.end;
    journal.prune(10).await.unwrap();
    let size_after = get_bounds(&journal).await.end;

    assert_eq!(size_before, size_after);
    assert_eq!(size_after, 20);

    journal.prune(20).await.unwrap();
    let size_after_all = get_bounds(&journal).await.end;
    assert_eq!(size_after, size_after_all);

    journal.sync().await.unwrap();
    drop(journal);

    let journal = factory("prune-retains-size".into()).await.unwrap();
    let size_after_close = get_bounds(&journal).await.end;
    assert_eq!(size_after_close, size_after_all);

    journal.destroy().await.unwrap();
}

/// Test using journal through [Contiguous] trait methods.
async fn test_through_trait<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("through-trait".into()).await.unwrap();

    let pos1 = Mutable::append(&mut journal, &42).await.unwrap();
    let pos2 = Mutable::append(&mut journal, &100).await.unwrap();

    assert_eq!(pos1, 0);
    assert_eq!(pos2, 1);

    let size = Contiguous::size(&journal).await;
    assert_eq!(size, 2);

    journal.destroy().await.unwrap();
}

/// Test replay after pruning items.
async fn test_replay_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("replay-after-prune".into()).await.unwrap();

    for i in 0..20u64 {
        journal.append(&(i * 10)).await.unwrap();
    }

    journal.prune(10).await.unwrap();

    {
        // Replay from a position that may or may not be pruned (section-aligned)
        // We replay from position 10 which should be safe
        let reader = journal.reader().await;
        let stream = reader.replay(NZUsize!(1024), 10).await.unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 10);
        for (i, (pos, value)) in items.iter().enumerate() {
            assert_eq!(*pos, (i + 10) as u64);
            assert_eq!(*value, ((i + 10) as u64) * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test pruning all items then appending new ones.
///
/// Verifies that positions continue consecutively increasing even after
/// pruning all retained items. Assumes items_per_blob = 10.
async fn test_prune_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("prune-then-append".into()).await.unwrap();

    // Append exactly one section (10 items)
    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    // Prune all items at a blob boundary.
    journal.prune(10).await.unwrap();
    assert!(get_bounds(&journal).await.is_empty());

    // Append new items after pruning - position should continue from 10
    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 10);

    assert_eq!(get_bounds(&journal).await.end, 11);

    journal.destroy().await.unwrap();
}

/// Test that positions remain stable after pruning and further appends.
async fn test_position_stability<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("position-stability".into()).await.unwrap();

    // Append initial items
    for i in 0..20u64 {
        journal.append(&(i * 100)).await.unwrap();
    }

    // Prune first 10
    journal.prune(10).await.unwrap();

    // Append more items
    for i in 20..25u64 {
        let pos = journal.append(&(i * 100)).await.unwrap();
        assert_eq!(pos, i);
    }

    // Verify reads work for retained items after pruning
    assert_eq!(read_item(&journal, 10).await.unwrap(), 1000);
    assert_eq!(read_item(&journal, 15).await.unwrap(), 1500);
    assert_eq!(read_item(&journal, 20).await.unwrap(), 2000);
    assert_eq!(read_item(&journal, 24).await.unwrap(), 2400);

    {
        // Replay from position 10 and verify positions
        let reader = journal.reader().await;
        let stream = reader.replay(NZUsize!(1024), 10).await.unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 15);
        for (i, (pos, value)) in items.iter().enumerate() {
            let expected_pos = (i + 10) as u64;
            assert_eq!(*pos, expected_pos);
            assert_eq!(*value, expected_pos * 100);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test sync behavior.
async fn test_sync_behavior<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("sync-behavior".into()).await.unwrap();

    for i in 0..5u64 {
        journal.append(&i).await.unwrap();
    }

    journal.sync().await.unwrap();

    // Verify operations work after sync
    assert_eq!(read_item(&journal, 0).await.unwrap(), 0);
    let pos = journal.append(&100).await.unwrap();
    assert_eq!(pos, 5);
    assert_eq!(read_item(&journal, 5).await.unwrap(), 100);

    assert_eq!(get_bounds(&journal).await.end, 6);

    journal.destroy().await.unwrap();
}

/// Test replay on an empty journal.
async fn test_replay_on_empty<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let journal = factory("replay-on-empty".into()).await.unwrap();

    {
        let reader = journal.reader().await;
        let stream = reader.replay(NZUsize!(1024), 0).await.unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 0);
    }

    journal.destroy().await.unwrap();
}

/// Test replay at exact size position.
async fn test_replay_at_exact_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("replay-at-exact-size".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    let bounds = get_bounds(&journal).await;

    {
        let reader = journal.reader().await;
        let stream = reader.replay(NZUsize!(1024), bounds.end).await.unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 0);
    }

    journal.destroy().await.unwrap();
}

/// Test multiple prunes with same min_position for idempotency.
async fn test_multiple_prunes<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("multiple-prunes".into()).await.unwrap();

    for i in 0..20u64 {
        journal.append(&i).await.unwrap();
    }

    let pruned1 = journal.prune(10).await.unwrap();
    let pruned2 = journal.prune(10).await.unwrap();

    assert!(pruned1);
    assert!(!pruned2); // Second prune should return false (nothing to prune)

    assert_eq!(get_bounds(&journal).await.end, 20);
    assert_eq!(read_item(&journal, 10).await.unwrap(), 10);
    assert_eq!(read_item(&journal, 19).await.unwrap(), 19);

    journal.destroy().await.unwrap();
}

/// Test pruning beyond the current size.
async fn test_prune_beyond_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("prune-beyond-size".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    // Prune with min_position > size should be safe
    journal.prune(100).await.unwrap();

    // Verify journal still works
    assert_eq!(get_bounds(&journal).await.end, 10);

    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(read_item(&journal, 10).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test basic persistence: append items, close, re-open, verify state.
async fn test_persistence_basic<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let test_name = "persistence-basic".to_string();

    // Create journal and append items
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..15u64 {
            let pos = journal.append(&(i * 10)).await.unwrap();
            assert_eq!(pos, i);
        }

        assert_eq!(get_bounds(&journal).await.end, 15);

        journal.sync().await.unwrap();
    }

    // Re-open and verify state persists
    {
        let journal = factory(test_name.clone()).await.unwrap();

        assert_eq!(get_bounds(&journal).await.end, 15);

        // Verify reads work after persistence
        for i in 0..15u64 {
            assert_eq!(read_item(&journal, i).await.unwrap(), i * 10);
        }

        // Replay and verify all items
        {
            let reader = journal.reader().await;
            let stream = reader.replay(NZUsize!(1024), 0).await.unwrap();
            futures::pin_mut!(stream);

            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                items.push(result.unwrap());
            }

            assert_eq!(items.len(), 15);
            for (i, (pos, value)) in items.iter().enumerate() {
                assert_eq!(*pos, i as u64);
                assert_eq!(*value, (i as u64) * 10);
            }
        }

        journal.destroy().await.unwrap();
    }
}

/// Test persistence after pruning: append, prune, close, re-open, verify pruned state.
async fn test_persistence_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let test_name = "persistence-after-prune".to_string();

    // Create journal, append items, and prune
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..25u64 {
            journal.append(&(i * 100)).await.unwrap();
        }

        // Prune first 10 items
        let pruned = journal.prune(10).await.unwrap();
        assert!(pruned);

        assert_eq!(get_bounds(&journal).await.end, 25);

        journal.sync().await.unwrap();
    }

    // Re-open and verify pruned state persists
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        // size should still be 25
        assert_eq!(get_bounds(&journal).await.end, 25);

        // Verify pruned positions cannot be read
        for i in 0..10u64 {
            assert!(matches!(
                read_item(&journal, i).await,
                Err(Error::ItemPruned(_))
            ));
        }

        // Verify non-pruned positions can be read
        for i in 10..25u64 {
            assert_eq!(read_item(&journal, i).await.unwrap(), i * 100);
        }

        // Replay from position 10 (first non-pruned position)
        {
            let reader = journal.reader().await;
            let stream = reader.replay(NZUsize!(1024), 10).await.unwrap();
            futures::pin_mut!(stream);

            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                items.push(result.unwrap());
            }

            assert_eq!(items.len(), 15);
            for (i, (pos, value)) in items.iter().enumerate() {
                let expected_pos = (i + 10) as u64;
                assert_eq!(*pos, expected_pos);
                assert_eq!(*value, expected_pos * 100);
            }
        }

        // Append more items after re-opening
        let pos = journal.append(&999).await.unwrap();
        assert_eq!(pos, 25);

        // Verify the newly appended item can be read
        assert_eq!(read_item(&journal, 25).await.unwrap(), 999);

        journal.destroy().await.unwrap();
    }
}

/// Test reading items by position.
pub(super) async fn test_read_by_position<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("read-by-position".into()).await.unwrap();

    for i in 0..1000u64 {
        journal.append(&(i * 100)).await.unwrap();
        assert_eq!(read_item(&journal, i).await.unwrap(), i * 100);
    }

    // Verify we can still read all items
    for i in 0..1000u64 {
        assert_eq!(read_item(&journal, i).await.unwrap(), i * 100);
    }

    journal.destroy().await.unwrap();
}

/// Test reading multiple items by position.
pub(super) async fn test_read_many<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("read-many".into()).await.unwrap();

    for i in 0..15u64 {
        journal.append(&(i * 100)).await.unwrap();
    }

    let reader = journal.reader().await;
    let items = reader.read_many(&[1, 4, 12]).await.unwrap();
    assert_eq!(items, vec![100, 400, 1200]);
    drop(reader);

    journal.destroy().await.unwrap();
}

/// Test read errors for out-of-range positions.
pub(super) async fn test_read_out_of_range<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("read-out-of-range".into()).await.unwrap();

    journal.append(&42).await.unwrap();

    // Try to read beyond size
    let result = read_item(&journal, 10).await;
    assert!(matches!(result, Err(Error::ItemOutOfRange(_))));

    journal.destroy().await.unwrap();
}

/// Test read after pruning.
pub(super) async fn test_read_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("read-after-prune".into()).await.unwrap();

    for i in 0..20u64 {
        journal.append(&i).await.unwrap();
    }

    journal.prune(10).await.unwrap();

    let bounds = get_bounds(&journal).await;
    let result = read_item(&journal, bounds.start - 1).await;
    assert!(matches!(result, Err(Error::ItemPruned(_))));

    journal.destroy().await.unwrap();
}

/// Test rewinding to the middle of the journal
#[allow(dead_code)]
async fn test_rewind_to_middle<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("rewind-to-middle".into()).await.unwrap();

    // Append 20 items
    for i in 0..20u64 {
        journal.append(&(i * 100)).await.unwrap();
    }

    // Rewind to 12 items
    journal.rewind(12).await.unwrap();

    assert_eq!(get_bounds(&journal).await.end, 12);

    // Verify first 12 items are still readable
    for i in 0..12u64 {
        assert_eq!(read_item(&journal, i).await.unwrap(), i * 100);
    }

    // Verify items 12-19 are gone
    for i in 12..20u64 {
        assert!(matches!(
            read_item(&journal, i).await,
            Err(Error::ItemOutOfRange(_))
        ));
    }

    // Next append should get position 12
    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 12);
    assert_eq!(read_item(&journal, 12).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test that split writers cannot rewind while the reader factory can still create snapshots.
async fn test_split_rewind_refused_while_readers_factory_alive<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("split-rewind-readers-live".into()).await.unwrap();

    for i in 0..15u64 {
        journal.append(&i).await.unwrap();
    }

    assert!(matches!(journal.rewind(5).await, Err(Error::BlobInUse(_))));

    let reader = journal.reader().await;
    assert_eq!(reader.bounds(), 0..15);
    assert_eq!(reader.read(14).await.unwrap(), 14);
    drop(reader);

    journal.destroy().await.unwrap();
}

/// Test rewinding to empty journal
#[allow(dead_code)]
async fn test_rewind_to_zero<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("rewind-to-zero".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    journal.rewind(0).await.unwrap();

    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.end, 0);
    assert!(bounds.is_empty());

    // Next append should get position 0
    let pos = journal.append(&42).await.unwrap();
    assert_eq!(pos, 0);

    journal.destroy().await.unwrap();
}

/// Test rewind to current size is no-op
#[allow(dead_code)]
async fn test_rewind_current_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("rewind-current-size".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    // Rewind to current size should be no-op
    journal.rewind(10).await.unwrap();
    assert_eq!(get_bounds(&journal).await.end, 10);

    journal.destroy().await.unwrap();
}

/// Test rewind with invalid forward size
#[allow(dead_code)]
async fn test_rewind_invalid_forward<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("rewind-invalid-forward".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    // Try to rewind forward (invalid)
    let result = journal.rewind(20).await;
    assert!(matches!(result, Err(Error::InvalidRewind(20))));

    journal.destroy().await.unwrap();
}

/// Test rewind to pruned position
#[allow(dead_code)]
async fn test_rewind_invalid_pruned<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("rewind-invalid-pruned".into()).await.unwrap();

    for i in 0..20u64 {
        journal.append(&i).await.unwrap();
    }

    // Prune first 10 items
    journal.prune(10).await.unwrap();

    // Try to rewind to pruned position (invalid)
    let result = journal.rewind(5).await;
    assert!(matches!(result, Err(Error::ItemPruned(5))));

    journal.destroy().await.unwrap();
}

/// Test rewind then append maintains position continuity.
/// Assumes items_per_blob = 10.
#[allow(dead_code)]
async fn test_rewind_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("rewind-then-append".into()).await.unwrap();

    // Append across a blob boundary (15 items = 1.5 blobs).
    for i in 0..15u64 {
        journal.append(&i).await.unwrap();
    }

    // Rewind to position 8 (within first section, not at boundary)
    journal.rewind(8).await.unwrap();

    // Append should continue from position 8
    let pos1 = journal.append(&888).await.unwrap();
    let pos2 = journal.append(&999).await.unwrap();

    assert_eq!(pos1, 8);
    assert_eq!(pos2, 9);
    assert_eq!(read_item(&journal, 8).await.unwrap(), 888);
    assert_eq!(read_item(&journal, 9).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test that rewinding to zero and then appending works
#[allow(dead_code)]
async fn test_rewind_zero_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("rewind-zero-then-append".into()).await.unwrap();

    // Append some items
    for i in 0..10u64 {
        journal.append(&(i * 100)).await.unwrap();
    }

    // Rewind to 0 (empty journal)
    journal.rewind(0).await.unwrap();

    // Verify journal is empty
    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.end, 0);
    assert!(bounds.is_empty());

    // Append should work
    let pos = journal.append(&42).await.unwrap();
    assert_eq!(pos, 0);
    assert_eq!(get_bounds(&journal).await.end, 1);
    assert_eq!(read_item(&journal, 0).await.unwrap(), 42);

    journal.destroy().await.unwrap();
}

/// Test rewinding after pruning to verify correct interaction between operations.
/// Assumes items_per_blob = 10.
#[allow(dead_code)]
async fn test_rewind_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("rewind-after-prune".into()).await.unwrap();

    // Append items across 3 blobs (30 items, assuming items_per_blob = 10).
    for i in 0..30u64 {
        journal.append(&(i * 100)).await.unwrap();
    }

    // Prune first section (items 0-9)
    journal.prune(10).await.unwrap();
    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.start, 10);

    // Rewind to position 20 (still in retained range)
    journal.rewind(20).await.unwrap();
    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.end, 20);
    assert_eq!(bounds.start, 10);

    // Verify items in range [bounds.start, 20) are still readable
    for i in bounds.start..20 {
        assert_eq!(read_item(&journal, i).await.unwrap(), i * 100);
    }

    // Attempt to rewind to a pruned position should fail
    let result = journal.rewind(5).await;
    assert!(matches!(result, Err(Error::ItemPruned(5))));

    // Verify journal state is unchanged after failed rewind
    let bounds = get_bounds(&journal).await;
    assert_eq!(bounds.end, 20);
    assert_eq!(bounds.start, 10);

    // Append should continue from position 20
    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 20);
    assert_eq!(read_item(&journal, 20).await.unwrap(), 999);
    assert_eq!(get_bounds(&journal).await.start, 10);

    journal.destroy().await.unwrap();
}

/// Test behavior at section boundaries.
/// Assumes items_per_blob = 10.
async fn test_section_boundary_behavior<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("section-boundary".into()).await.unwrap();

    // Append exactly one section worth of items (10 items)
    for i in 0..10u64 {
        let pos = journal.append(&(i * 100)).await.unwrap();
        assert_eq!(pos, i);
    }

    // Verify we're at a blob boundary.
    assert_eq!(get_bounds(&journal).await.end, 10);

    // Append one more item to cross the boundary
    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(get_bounds(&journal).await.end, 11);

    // Prune exactly at the blob boundary.
    journal.prune(10).await.unwrap();
    assert_eq!(get_bounds(&journal).await.start, 10);

    // Verify only the item after the boundary is readable
    assert!(matches!(
        read_item(&journal, 9).await,
        Err(Error::ItemPruned(_))
    ));
    assert_eq!(read_item(&journal, 10).await.unwrap(), 999);

    // Append another item to move past the boundary
    let pos = journal.append(&888).await.unwrap();
    assert_eq!(pos, 11);
    assert_eq!(get_bounds(&journal).await.end, 12);

    journal.destroy().await.unwrap();
}

/// Test that destroy properly cleans up storage and re-init starts fresh.
///
/// Verifies that after destroying a journal, a new journal with the same
/// partition name starts from a clean state.
async fn test_destroy_and_reinit<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let test_name = "destroy-and-reinit".to_string();

    // Create journal and add data
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..20u64 {
            journal.append(&(i * 100)).await.unwrap();
        }

        journal.prune(10).await.unwrap();
        assert_eq!(get_bounds(&journal).await.end, 20);
        assert!(!get_bounds(&journal).await.is_empty());

        // Explicitly destroy the journal
        journal.destroy().await.unwrap();
    }

    // Re-initialize with the same partition name
    {
        let journal = factory(test_name.clone()).await.unwrap();

        // Journal should be completely empty, not contain previous data
        let bounds = get_bounds(&journal).await;
        assert_eq!(bounds.end, 0);
        assert!(bounds.is_empty());

        // Replay should yield no items
        {
            let reader = journal.reader().await;
            let stream = reader.replay(NZUsize!(1024), 0).await.unwrap();
            futures::pin_mut!(stream);

            let mut items = Vec::new();
            while let Some(result) = stream.next().await {
                items.push(result.unwrap());
            }
            assert!(items.is_empty());
        }

        journal.destroy().await.unwrap();
    }
}

/// Test append_many with empty slice returns an error.
async fn test_append_many_empty<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("append-many-empty".into()).await.unwrap();

    // Append some items first.
    journal.append(&10).await.unwrap();
    journal.append(&20).await.unwrap();

    // append_many with empty slice should return an error.
    assert!(matches!(
        journal.append_many(Many::Flat(&[])).await,
        Err(Error::EmptyAppend)
    ));
    assert_eq!(get_bounds(&journal).await.end, 2);

    journal.destroy().await.unwrap();
}

/// Test append_many with multiple items.
async fn test_append_many_basic<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("append-many-basic".into()).await.unwrap();

    let pos = journal
        .append_many(Many::Flat(&[100, 200, 300]))
        .await
        .unwrap();
    assert_eq!(pos, 2);
    assert_eq!(get_bounds(&journal).await.end, 3);

    assert_eq!(read_item(&journal, 0).await.unwrap(), 100);
    assert_eq!(read_item(&journal, 1).await.unwrap(), 200);
    assert_eq!(read_item(&journal, 2).await.unwrap(), 300);

    journal.destroy().await.unwrap();
}

/// Test append_many across blob boundaries (items_per_blob = 10).
async fn test_append_many_across_sections<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("append-many-sections".into()).await.unwrap();

    // Append 25 items in one call, crossing section boundaries at 10 and 20.
    let items: Vec<u64> = (0..25).map(|i| i * 10).collect();
    let pos = journal.append_many(Many::Flat(&items)).await.unwrap();
    assert_eq!(pos, 24);
    assert_eq!(get_bounds(&journal).await.end, 25);

    for i in 0..25u64 {
        assert_eq!(read_item(&journal, i).await.unwrap(), i * 10);
    }

    journal.destroy().await.unwrap();
}

/// Test append_many followed by single appends.
async fn test_append_many_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("append-many-then-single".into()).await.unwrap();

    journal
        .append_many(Many::Flat(&[10, 20, 30]))
        .await
        .unwrap();
    let pos = journal.append(&40).await.unwrap();
    assert_eq!(pos, 3);

    assert_eq!(read_item(&journal, 0).await.unwrap(), 10);
    assert_eq!(read_item(&journal, 1).await.unwrap(), 20);
    assert_eq!(read_item(&journal, 2).await.unwrap(), 30);
    assert_eq!(read_item(&journal, 3).await.unwrap(), 40);

    journal.destroy().await.unwrap();
}

/// Test append_many with a single item behaves like append.
async fn test_append_many_single_item<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: TestSplitJournal,
{
    let mut journal = factory("append-many-single".into()).await.unwrap();

    let pos = journal.append_many(Many::Flat(&[42])).await.unwrap();
    assert_eq!(pos, 0);
    assert_eq!(read_item(&journal, 0).await.unwrap(), 42);

    journal.destroy().await.unwrap();
}
