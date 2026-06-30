//! Generic test suite for [Contiguous] trait implementations.

use super::{fixed, variable, Contiguous, Many};
use crate::journal::{contiguous::Mutable, Error};
use commonware_macros::boxed;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, reschedule, Handle, Runner as _, Spawner as _,
    Supervisor as _,
};
use commonware_utils::{NZUsize, NZU16, NZU64};
use futures::{future::BoxFuture, StreamExt};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

pub(super) mod partition_sync_fault {
    use commonware_runtime::{
        deterministic, telemetry::metrics, Blob, Clock, Error, Handle, IoBufs, IoBufsMut, Metrics,
        Name, Storage, Supervisor,
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
                return Err(Error::Io(
                    IoError::other("injected partition sync fault").into(),
                ));
            }
            self.inner.sync().await
        }

        async fn start_sync(&self) -> Handle<()> {
            if self.partition == self.fail_partition {
                return Handle::ready(self.sync().await);
            }
            self.inner.start_sync().await
        }
    }
}

/// A [Context] wrapper whose blob `start_sync` defers completion until [`Control::release`], so a
/// test can observe (and act on) the journal while a real backend sync is genuinely in flight.
pub(super) mod delayed_start_sync {
    use commonware_runtime::{
        deterministic, telemetry::metrics, Blob, Clock, Error, Handle, IoBufs, IoBufsMut, Metrics,
        Name, Storage, Supervisor,
    };
    use commonware_utils::sync::Notify;
    use governor::clock::{Clock as GovernorClock, ReasonablyRealtime};
    use std::{
        future::Future,
        io::Error as IoError,
        ops::RangeInclusive,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, SystemTime},
    };

    /// Shared control over every blob's deferred `start_sync` produced by one [Context].
    pub(in crate::journal::contiguous) struct Control {
        released: AtomicBool,
        release: Notify,
        fail: AtomicBool,
        starts: AtomicUsize,
        start_waits: AtomicUsize,
        start_completions: AtomicUsize,
    }

    impl Control {
        pub(in crate::journal::contiguous) fn new() -> Arc<Self> {
            Arc::new(Self {
                released: AtomicBool::new(false),
                release: Notify::new(),
                fail: AtomicBool::new(false),
                starts: AtomicUsize::new(0),
                start_waits: AtomicUsize::new(0),
                start_completions: AtomicUsize::new(0),
            })
        }

        /// Arm every in-flight sync to resolve to an error instead of syncing.
        pub(in crate::journal::contiguous) fn arm_fail(&self) {
            self.fail.store(true, Ordering::SeqCst);
        }

        /// Let every in-flight (and future) `start_sync` proceed to completion.
        pub(in crate::journal::contiguous) fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            self.release.notify_waiters();
        }

        /// Number of `start_sync` calls issued.
        pub(in crate::journal::contiguous) fn starts(&self) -> usize {
            self.starts.load(Ordering::SeqCst)
        }

        /// Number of in-flight syncs that began waiting for release.
        pub(in crate::journal::contiguous) fn start_waits(&self) -> usize {
            self.start_waits.load(Ordering::SeqCst)
        }

        /// Number of in-flight syncs that completed durably.
        pub(in crate::journal::contiguous) fn start_completions(&self) -> usize {
            self.start_completions.load(Ordering::SeqCst)
        }

        async fn wait_released(&self) {
            while !self.released.load(Ordering::SeqCst) {
                self.release.notified().await;
            }
        }
    }

    pub(in crate::journal::contiguous) struct Context {
        inner: deterministic::Context,
        control: Arc<Control>,
    }

    impl Context {
        pub(in crate::journal::contiguous) fn new(
            inner: deterministic::Context,
            control: Arc<Control>,
        ) -> Self {
            Self { inner, control }
        }
    }

    #[derive(Clone)]
    pub(in crate::journal::contiguous) struct DelayedStartSyncBlob<B: Blob> {
        inner: B,
        control: Arc<Control>,
    }

    impl Supervisor for Context {
        fn name(&self) -> Name {
            self.inner.name()
        }

        fn child(&self, label: &'static str) -> Self {
            Self {
                inner: self.inner.child(label),
                control: self.control.clone(),
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
        type Blob = DelayedStartSyncBlob<<deterministic::Context as Storage>::Blob>;

        async fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: RangeInclusive<u16>,
        ) -> Result<(Self::Blob, u64, u16), Error> {
            let (inner, len, version) =
                self.inner.open_versioned(partition, name, versions).await?;
            Ok((
                DelayedStartSyncBlob {
                    inner,
                    control: self.control.clone(),
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

    impl<B: Blob> Blob for DelayedStartSyncBlob<B> {
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
            self.inner.sync().await
        }

        async fn start_sync(&self) -> Handle<()> {
            self.control.starts.fetch_add(1, Ordering::SeqCst);
            let control = self.control.clone();
            let inner = self.inner.clone();
            Handle::from_future(async move {
                control.start_waits.fetch_add(1, Ordering::SeqCst);
                control.wait_released().await;
                if control.fail.load(Ordering::SeqCst) {
                    return Err(Error::Io(
                        IoError::other("injected start_sync failure").into(),
                    ));
                }
                inner.start_sync().await.await?;
                control.start_completions.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
        }
    }
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
    J: Mutable<Item = u64>,
{
    let counter = AtomicUsize::new(0);
    let indexed_factory = |name: String| {
        let idx = counter.fetch_add(1, Ordering::SeqCst);
        factory(name, idx)
    };

    test_empty_journal_bounds(&indexed_factory).await;
    test_bounds_with_items(&indexed_factory).await;
    test_bounds_after_prune(&indexed_factory).await;
    test_append_and_size(&indexed_factory).await;
    test_sequential_appends(&indexed_factory).await;
    test_replay_from_start(&indexed_factory).await;
    test_replay_from_middle(&indexed_factory).await;
    test_replay_from_unsealed_tail(&indexed_factory).await;
    test_replay_with_small_buffer(&indexed_factory).await;
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
    test_rewind_to_middle(&indexed_factory).await;
    test_rewind_to_zero(&indexed_factory).await;
    test_rewind_current_size(&indexed_factory).await;
    test_rewind_invalid_forward(&indexed_factory).await;
    test_rewind_invalid_pruned(&indexed_factory).await;
    test_rewind_then_append(&indexed_factory).await;
    test_rewind_zero_then_append(&indexed_factory).await;
    test_rewind_after_prune(&indexed_factory).await;
    test_section_boundary_behavior(&indexed_factory).await;
    test_destroy_and_reinit(&indexed_factory).await;
    test_append_many_empty(&indexed_factory).await;
    test_append_many_basic(&indexed_factory).await;
    test_append_many_across_sections(&indexed_factory).await;
    test_append_many_then_append(&indexed_factory).await;
    test_append_many_single_item(&indexed_factory).await;
}

/// Test that an empty journal has empty bounds (start == end == 0).
async fn test_empty_journal_bounds<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let journal = factory("empty".into()).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, 0);
    assert!(bounds.is_empty());
    journal.destroy().await.unwrap();
}

/// Test that bounds returns 0..size for journal with items.
async fn test_bounds_with_items<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("bounds-with-items".into()).await.unwrap();

    // Append some items
    for i in 0..10 {
        journal.append(&(i * 100)).await.unwrap();
    }

    let bounds = journal.bounds();
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
    J: Mutable<Item = u64>,
{
    let mut journal = factory("bounds-after-prune".into()).await.unwrap();

    // Append items across multiple sections
    for i in 0..30 {
        journal.append(&(i * 100)).await.unwrap();
    }

    // Initially bounds should be 0..30
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 0);
    assert_eq!(bounds.end, 30);

    // Prune first section - trait only guarantees section-aligned pruning
    journal.prune(10).await.unwrap();

    // Assumed blob-aligned pruning and items_per_blob = 10.
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 10);
    assert_eq!(bounds.end, 30);

    // Prune more
    journal.prune(25).await.unwrap();

    // bounds.start should have advanced to 20 (section-aligned)
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 20);
    assert_eq!(bounds.end, 30);

    // Prune all
    journal.prune(30).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 30);
    assert_eq!(bounds.end, 30);
    assert!(bounds.is_empty());

    // Drop and reopen
    journal.sync().await.unwrap();
    drop(journal);
    let journal = factory("bounds-after-prune".into()).await.unwrap();
    let bounds = journal.bounds();
    assert!(bounds.is_empty());
    journal.destroy().await.unwrap();
}

/// Test that append returns sequential positions and size increments.
async fn test_append_and_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-and-size".into()).await.unwrap();

    let pos1 = journal.append(&100).await.unwrap();
    let pos2 = journal.append(&200).await.unwrap();
    let pos3 = journal.append(&300).await.unwrap();

    assert_eq!(pos1, 0);
    assert_eq!(pos2, 1);
    assert_eq!(pos3, 2);
    assert_eq!(journal.bounds().end, 3);

    // Verify values can be read back
    assert_eq!(journal.read(0).await.unwrap(), 100);
    assert_eq!(journal.read(1).await.unwrap(), 200);
    assert_eq!(journal.read(2).await.unwrap(), 300);

    journal.destroy().await.unwrap();
}

/// Test appending many items across section boundaries.
async fn test_sequential_appends<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("sequential-appends".into()).await.unwrap();

    for i in 0..25u64 {
        let pos = journal.append(&(i * 10)).await.unwrap();
        assert_eq!(pos, i);
    }

    assert_eq!(journal.bounds().end, 25);

    for i in 0..25u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 10);
    }

    journal.destroy().await.unwrap();
}

/// Test replay from the start of the journal.
async fn test_replay_from_start<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-from-start".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&(i * 10)).await.unwrap();
    }

    {
        let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
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
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-from-middle".into()).await.unwrap();

    for i in 0..15u64 {
        journal.append(&(i * 10)).await.unwrap();
    }

    {
        let stream = journal.replay(7, NZUsize!(1024)).await.unwrap();
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

/// Test replay starting in the writable tail.
async fn test_replay_from_unsealed_tail<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-from-unsealed-tail".into()).await.unwrap();

    for i in 0..17u64 {
        journal.append(&(i * 10)).await.unwrap();
    }

    {
        let stream = journal.replay(13, NZUsize!(1024)).await.unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 4);
        for (i, (pos, value)) in items.iter().enumerate() {
            let expected_pos = (i + 13) as u64;
            assert_eq!(*pos, expected_pos);
            assert_eq!(*value, expected_pos * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test replay with a small buffer.
async fn test_replay_with_small_buffer<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-with-small-buffer".into()).await.unwrap();

    for i in 0..25u64 {
        journal.append(&(i * 10)).await.unwrap();
    }

    {
        let stream = journal.replay(0, NZUsize!(9)).await.unwrap();
        futures::pin_mut!(stream);

        let mut items = Vec::new();
        while let Some(result) = stream.next().await {
            items.push(result.unwrap());
        }

        assert_eq!(items.len(), 25);
        for (i, (pos, value)) in items.iter().enumerate() {
            assert_eq!(*pos, i as u64);
            assert_eq!(*value, (i as u64) * 10);
        }
    }

    journal.destroy().await.unwrap();
}

/// Test that size is unchanged after pruning.
async fn test_prune_retains_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("prune-retains-size".into()).await.unwrap();

    for i in 0..20u64 {
        journal.append(&i).await.unwrap();
    }

    let size_before = journal.bounds().end;
    journal.prune(10).await.unwrap();
    let size_after = journal.bounds().end;

    assert_eq!(size_before, size_after);
    assert_eq!(size_after, 20);

    journal.prune(20).await.unwrap();
    let size_after_all = journal.bounds().end;
    assert_eq!(size_after, size_after_all);

    journal.sync().await.unwrap();
    drop(journal);

    let journal = factory("prune-retains-size".into()).await.unwrap();
    let size_after_close = journal.bounds().end;
    assert_eq!(size_after_close, size_after_all);

    journal.destroy().await.unwrap();
}

/// Test using journal through [Contiguous] trait methods.
async fn test_through_trait<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("through-trait".into()).await.unwrap();

    let pos1 = Mutable::append(&mut journal, &42).await.unwrap();
    let pos2 = Mutable::append(&mut journal, &100).await.unwrap();

    assert_eq!(pos1, 0);
    assert_eq!(pos2, 1);

    let size = Contiguous::bounds(&journal).end;
    assert_eq!(size, 2);

    journal.destroy().await.unwrap();
}

/// Test replay after pruning items.
async fn test_replay_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-after-prune".into()).await.unwrap();

    for i in 0..20u64 {
        journal.append(&(i * 10)).await.unwrap();
    }

    journal.prune(10).await.unwrap();

    {
        // Replay from a position that may or may not be pruned (section-aligned)
        // We replay from position 10 which should be safe
        let stream = journal.replay(10, NZUsize!(1024)).await.unwrap();
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
    J: Mutable<Item = u64>,
{
    let mut journal = factory("prune-then-append".into()).await.unwrap();

    // Append exactly one section (10 items)
    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    // Prune all items at a blob boundary.
    journal.prune(10).await.unwrap();
    assert!(journal.bounds().is_empty());

    // Append new items after pruning - position should continue from 10
    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 10);

    assert_eq!(journal.bounds().end, 11);

    journal.destroy().await.unwrap();
}

/// Test that positions remain stable after pruning and further appends.
async fn test_position_stability<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
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
    assert_eq!(journal.read(10).await.unwrap(), 1000);
    assert_eq!(journal.read(15).await.unwrap(), 1500);
    assert_eq!(journal.read(20).await.unwrap(), 2000);
    assert_eq!(journal.read(24).await.unwrap(), 2400);

    {
        // Replay from position 10 and verify positions
        let stream = journal.replay(10, NZUsize!(1024)).await.unwrap();
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
    J: Mutable<Item = u64>,
{
    let mut journal = factory("sync-behavior".into()).await.unwrap();

    for i in 0..5u64 {
        journal.append(&i).await.unwrap();
    }

    journal.sync().await.unwrap();

    // Verify operations work after sync
    assert_eq!(journal.read(0).await.unwrap(), 0);
    let pos = journal.append(&100).await.unwrap();
    assert_eq!(pos, 5);
    assert_eq!(journal.read(5).await.unwrap(), 100);

    assert_eq!(journal.bounds().end, 6);

    journal.destroy().await.unwrap();
}

/// Test replay on an empty journal.
async fn test_replay_on_empty<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let journal = factory("replay-on-empty".into()).await.unwrap();

    {
        let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
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
    J: Mutable<Item = u64>,
{
    let mut journal = factory("replay-at-exact-size".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    let bounds = journal.bounds();

    {
        let stream = journal.replay(bounds.end, NZUsize!(1024)).await.unwrap();
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
    J: Mutable<Item = u64>,
{
    let mut journal = factory("multiple-prunes".into()).await.unwrap();

    for i in 0..20u64 {
        journal.append(&i).await.unwrap();
    }

    let pruned1 = journal.prune(10).await.unwrap();
    let pruned2 = journal.prune(10).await.unwrap();

    assert!(pruned1);
    assert!(!pruned2); // Second prune should return false (nothing to prune)

    assert_eq!(journal.bounds().end, 20);
    assert_eq!(journal.read(10).await.unwrap(), 10);
    assert_eq!(journal.read(19).await.unwrap(), 19);

    journal.destroy().await.unwrap();
}

/// Test pruning beyond the current size.
async fn test_prune_beyond_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("prune-beyond-size".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    // Prune with min_position > size should be safe
    journal.prune(100).await.unwrap();

    // Verify journal still works
    assert_eq!(journal.bounds().end, 10);

    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(journal.read(10).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test basic persistence: append items, close, re-open, verify state.
async fn test_persistence_basic<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let test_name = "persistence-basic".to_string();

    // Create journal and append items
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..15u64 {
            let pos = journal.append(&(i * 10)).await.unwrap();
            assert_eq!(pos, i);
        }

        assert_eq!(journal.bounds().end, 15);

        journal.sync().await.unwrap();
    }

    // Re-open and verify state persists
    {
        let journal = factory(test_name.clone()).await.unwrap();

        assert_eq!(journal.bounds().end, 15);

        // Verify reads work after persistence
        for i in 0..15u64 {
            assert_eq!(journal.read(i).await.unwrap(), i * 10);
        }

        // Replay and verify all items
        {
            let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
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
    J: Mutable<Item = u64>,
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

        assert_eq!(journal.bounds().end, 25);

        journal.sync().await.unwrap();
    }

    // Re-open and verify pruned state persists
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        // size should still be 25
        assert_eq!(journal.bounds().end, 25);

        // Verify pruned positions cannot be read
        for i in 0..10u64 {
            assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
        }

        // Verify non-pruned positions can be read
        for i in 10..25u64 {
            assert_eq!(journal.read(i).await.unwrap(), i * 100);
        }

        // Replay from position 10 (first non-pruned position)
        {
            let stream = journal.replay(10, NZUsize!(1024)).await.unwrap();
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
        assert_eq!(journal.read(25).await.unwrap(), 999);

        journal.destroy().await.unwrap();
    }
}

/// Test reading items by position.
pub(super) async fn test_read_by_position<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("read-by-position".into()).await.unwrap();

    for i in 0..1000u64 {
        journal.append(&(i * 100)).await.unwrap();
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    // Verify we can still read all items
    for i in 0..1000u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    journal.destroy().await.unwrap();
}

/// Test reading multiple items by position.
pub(super) async fn test_read_many<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("read-many".into()).await.unwrap();

    for i in 0..15u64 {
        journal.append(&(i * 100)).await.unwrap();
    }

    let items = journal.read_many(&[1, 4, 12]).await.unwrap();
    assert_eq!(items, vec![100, 400, 1200]);

    journal.destroy().await.unwrap();
}

/// Test read errors for out-of-range positions.
pub(super) async fn test_read_out_of_range<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("read-out-of-range".into()).await.unwrap();

    journal.append(&42).await.unwrap();

    // Try to read beyond size
    let result = journal.read(10).await;
    assert!(matches!(result, Err(Error::ItemOutOfRange(_))));

    journal.destroy().await.unwrap();
}

/// Test read after pruning.
pub(super) async fn test_read_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("read-after-prune".into()).await.unwrap();

    for i in 0..20u64 {
        journal.append(&i).await.unwrap();
    }

    journal.prune(10).await.unwrap();

    let bounds = journal.bounds();
    let result = journal.read(bounds.start - 1).await;
    assert!(matches!(result, Err(Error::ItemPruned(_))));

    journal.destroy().await.unwrap();
}

/// Test rewinding to the middle of the journal
async fn test_rewind_to_middle<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-to-middle".into()).await.unwrap();

    // Append 20 items
    for i in 0..20u64 {
        journal.append(&(i * 100)).await.unwrap();
    }

    // Rewind to 12 items
    journal.rewind(12).await.unwrap();

    assert_eq!(journal.bounds().end, 12);

    // Verify first 12 items are still readable
    for i in 0..12u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    // Verify items 12-19 are gone
    for i in 12..20u64 {
        assert!(matches!(
            journal.read(i).await,
            Err(Error::ItemOutOfRange(_))
        ));
    }

    // Next append should get position 12
    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 12);
    assert_eq!(journal.read(12).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test rewinding to empty journal
async fn test_rewind_to_zero<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-to-zero".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    journal.rewind(0).await.unwrap();

    let bounds = journal.bounds();
    assert_eq!(bounds.end, 0);
    assert!(bounds.is_empty());

    // Next append should get position 0
    let pos = journal.append(&42).await.unwrap();
    assert_eq!(pos, 0);

    journal.destroy().await.unwrap();
}

/// Test rewind to current size is no-op
async fn test_rewind_current_size<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-current-size".into()).await.unwrap();

    for i in 0..10u64 {
        journal.append(&i).await.unwrap();
    }

    // Rewind to current size should be no-op
    journal.rewind(10).await.unwrap();
    assert_eq!(journal.bounds().end, 10);

    journal.destroy().await.unwrap();
}

/// Test rewind with invalid forward size
async fn test_rewind_invalid_forward<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
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
async fn test_rewind_invalid_pruned<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
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
async fn test_rewind_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
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
    assert_eq!(journal.read(8).await.unwrap(), 888);
    assert_eq!(journal.read(9).await.unwrap(), 999);

    journal.destroy().await.unwrap();
}

/// Test that rewinding to zero and then appending works
async fn test_rewind_zero_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-zero-then-append".into()).await.unwrap();

    // Append some items
    for i in 0..10u64 {
        journal.append(&(i * 100)).await.unwrap();
    }

    // Rewind to 0 (empty journal)
    journal.rewind(0).await.unwrap();

    // Verify journal is empty
    let bounds = journal.bounds();
    assert_eq!(bounds.end, 0);
    assert!(bounds.is_empty());

    // Append should work
    let pos = journal.append(&42).await.unwrap();
    assert_eq!(pos, 0);
    assert_eq!(journal.bounds().end, 1);
    assert_eq!(journal.read(0).await.unwrap(), 42);

    journal.destroy().await.unwrap();
}

/// Test rewinding after pruning to verify correct interaction between operations.
/// Assumes items_per_blob = 10.
async fn test_rewind_after_prune<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("rewind-after-prune".into()).await.unwrap();

    // Append items across 3 blobs (30 items, assuming items_per_blob = 10).
    for i in 0..30u64 {
        journal.append(&(i * 100)).await.unwrap();
    }

    // Prune first section (items 0-9)
    journal.prune(10).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.start, 10);

    // Rewind to position 20 (still in retained range)
    journal.rewind(20).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.end, 20);
    assert_eq!(bounds.start, 10);

    // Verify items in range [bounds.start, 20) are still readable
    for i in bounds.start..20 {
        assert_eq!(journal.read(i).await.unwrap(), i * 100);
    }

    // Attempt to rewind to a pruned position should fail
    let result = journal.rewind(5).await;
    assert!(matches!(result, Err(Error::ItemPruned(5))));

    // Verify journal state is unchanged after failed rewind
    let bounds = journal.bounds();
    assert_eq!(bounds.end, 20);
    assert_eq!(bounds.start, 10);

    // Append should continue from position 20
    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 20);
    assert_eq!(journal.read(20).await.unwrap(), 999);
    assert_eq!(journal.bounds().start, 10);

    journal.destroy().await.unwrap();
}

/// Test behavior at section boundaries.
/// Assumes items_per_blob = 10.
async fn test_section_boundary_behavior<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("section-boundary".into()).await.unwrap();

    // Append exactly one section worth of items (10 items)
    for i in 0..10u64 {
        let pos = journal.append(&(i * 100)).await.unwrap();
        assert_eq!(pos, i);
    }

    // Verify we're at a blob boundary.
    assert_eq!(journal.bounds().end, 10);

    // Append one more item to cross the boundary
    let pos = journal.append(&999).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(journal.bounds().end, 11);

    // Prune exactly at the blob boundary.
    journal.prune(10).await.unwrap();
    assert_eq!(journal.bounds().start, 10);

    // Verify only the item after the boundary is readable
    assert!(matches!(journal.read(9).await, Err(Error::ItemPruned(_))));
    assert_eq!(journal.read(10).await.unwrap(), 999);

    // Append another item to move past the boundary
    let pos = journal.append(&888).await.unwrap();
    assert_eq!(pos, 11);
    assert_eq!(journal.bounds().end, 12);

    // Rewind to exactly the blob boundary (position 10).
    // This leaves bounds.end=10, bounds.start=10, making the journal fully pruned
    journal.rewind(10).await.unwrap();
    let bounds = journal.bounds();
    assert_eq!(bounds.end, 10);
    assert!(bounds.is_empty());

    // Append after rewinding to boundary should continue from position 10
    let pos = journal.append(&777).await.unwrap();
    assert_eq!(pos, 10);
    assert_eq!(journal.bounds().end, 11);
    assert_eq!(journal.read(10).await.unwrap(), 777);
    assert_eq!(journal.bounds().start, 10);

    journal.destroy().await.unwrap();
}

/// Test that destroy properly cleans up storage and re-init starts fresh.
///
/// Verifies that after destroying a journal, a new journal with the same
/// partition name starts from a clean state.
async fn test_destroy_and_reinit<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let test_name = "destroy-and-reinit".to_string();

    // Create journal and add data
    {
        let mut journal = factory(test_name.clone()).await.unwrap();

        for i in 0..20u64 {
            journal.append(&(i * 100)).await.unwrap();
        }

        journal.prune(10).await.unwrap();
        assert_eq!(journal.bounds().end, 20);
        assert!(!journal.bounds().is_empty());

        // Explicitly destroy the journal
        journal.destroy().await.unwrap();
    }

    // Re-initialize with the same partition name
    {
        let journal = factory(test_name.clone()).await.unwrap();

        // Journal should be completely empty, not contain previous data
        let bounds = journal.bounds();
        assert_eq!(bounds.end, 0);
        assert!(bounds.is_empty());

        // Replay should yield no items
        {
            let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
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
    J: Mutable<Item = u64>,
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
    assert_eq!(journal.bounds().end, 2);

    journal.destroy().await.unwrap();
}

/// Test append_many with multiple items.
async fn test_append_many_basic<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-many-basic".into()).await.unwrap();

    let pos = journal
        .append_many(Many::Flat(&[100, 200, 300]))
        .await
        .unwrap();
    assert_eq!(pos, 2);
    assert_eq!(journal.bounds().end, 3);

    assert_eq!(journal.read(0).await.unwrap(), 100);
    assert_eq!(journal.read(1).await.unwrap(), 200);
    assert_eq!(journal.read(2).await.unwrap(), 300);

    journal.destroy().await.unwrap();
}

/// Test append_many across blob boundaries (items_per_blob = 10).
async fn test_append_many_across_sections<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-many-sections".into()).await.unwrap();

    // Append 25 items in one call, crossing section boundaries at 10 and 20.
    let items: Vec<u64> = (0..25).map(|i| i * 10).collect();
    let pos = journal.append_many(Many::Flat(&items)).await.unwrap();
    assert_eq!(pos, 24);
    assert_eq!(journal.bounds().end, 25);

    for i in 0..25u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 10);
    }

    journal.destroy().await.unwrap();
}

/// Test append_many followed by single appends.
async fn test_append_many_then_append<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-many-then-single".into()).await.unwrap();

    journal
        .append_many(Many::Flat(&[10, 20, 30]))
        .await
        .unwrap();
    let pos = journal.append(&40).await.unwrap();
    assert_eq!(pos, 3);

    assert_eq!(journal.read(0).await.unwrap(), 10);
    assert_eq!(journal.read(1).await.unwrap(), 20);
    assert_eq!(journal.read(2).await.unwrap(), 30);
    assert_eq!(journal.read(3).await.unwrap(), 40);

    journal.destroy().await.unwrap();
}

/// Test append_many with a single item behaves like append.
async fn test_append_many_single_item<F, J>(factory: &F)
where
    F: Fn(String) -> BoxFuture<'static, Result<J, Error>>,
    J: Mutable<Item = u64>,
{
    let mut journal = factory("append-many-single".into()).await.unwrap();

    let pos = journal.append_many(Many::Flat(&[42])).await.unwrap();
    assert_eq!(pos, 0);
    assert_eq!(journal.read(0).await.unwrap(), 42);

    journal.destroy().await.unwrap();
}

trait CommitHandle: Mutable<Item = u64> {
    fn commit_handle(&mut self) -> impl Future<Output = Handle<()>> + Send;
}

impl<E: crate::Context> CommitHandle for fixed::Journal<E, u64> {
    fn commit_handle(&mut self) -> impl Future<Output = Handle<()>> + Send {
        Self::start_commit(self)
    }
}

impl<E: crate::Context> CommitHandle for variable::Journal<E, u64> {
    fn commit_handle(&mut self) -> impl Future<Output = Handle<()>> + Send {
        Self::start_commit(self)
    }
}

#[boxed]
async fn test_commit_handle_durability<F, Fut, J>(factory: F)
where
    F: Fn(&'static str) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: CommitHandle,
{
    let mut journal = factory("a").await.unwrap();
    for i in 0..7u64 {
        journal.append(&(i * 10)).await.unwrap();
    }
    let handle = journal.commit_handle().await;
    handle.await.unwrap();
    let size = journal.bounds().end;
    drop(journal);

    let journal = factory("b").await.unwrap();
    assert_eq!(journal.bounds().end, size);
    for i in 0..7u64 {
        assert_eq!(journal.read(i).await.unwrap(), i * 10);
    }
    journal.destroy().await.unwrap();
}

#[test]
fn test_fixed_commit_handle_durability() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = fixed::Config {
            partition: "fixed-commit-handle".into(),
            items_per_blob: NZU64!(3),
            page_cache: CacheRef::from_pooler(&context, NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
        };
        test_commit_handle_durability(|label| {
            let cfg = cfg.clone();
            fixed::Journal::<_, u64>::init(context.child(label), cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_commit_handle_durability() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let cfg = variable::Config {
            partition: "variable-commit-handle".into(),
            items_per_section: NZU64!(3),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::from_pooler(&context, NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
        };
        test_commit_handle_durability(|label| {
            let cfg = cfg.clone();
            variable::Journal::<_, u64>::init(context.child(label), cfg)
        })
        .await;
    });
}

/// A commit handle must not block journal use while backend sync is pending.
#[boxed]
async fn test_commit_handle_overlaps_work<F, Fut, J>(
    context: deterministic::Context,
    control: Arc<delayed_start_sync::Control>,
    make: F,
) where
    F: Fn(delayed_start_sync::Context) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: CommitHandle,
{
    let mut journal = make(delayed_start_sync::Context::new(
        context.child("a"),
        control.clone(),
    ))
    .await
    .unwrap();
    for i in 0..4u64 {
        journal.append(&i).await.unwrap();
    }

    let handle = journal.commit_handle().await;
    assert!(control.starts() >= 1);
    assert_eq!(control.start_completions(), 0);

    // Observe the sync while the journal keeps working.
    let waiter = context
        .child("await_sync")
        .spawn(|_| async move { handle.await.unwrap() });
    while control.start_waits() == 0 {
        reschedule().await;
    }

    // Append/read complete before sync.
    journal.append(&999).await.unwrap();
    assert_eq!(journal.read(0).await.unwrap(), 0);
    assert_eq!(
        control.start_completions(),
        0,
        "the journal made progress while the sync was still in flight"
    );

    control.release();
    waiter.await.unwrap();
    assert!(control.start_completions() >= 1);

    // Mid-sync append is durable after the next commit.
    let handle = journal.commit_handle().await;
    handle.await.unwrap();
    drop(journal);

    let journal = make(delayed_start_sync::Context::new(
        context.child("b"),
        control.clone(),
    ))
    .await
    .unwrap();
    assert_eq!(journal.bounds().end, 5);
    for i in 0..4u64 {
        assert_eq!(journal.read(i).await.unwrap(), i);
    }
    assert_eq!(journal.read(4).await.unwrap(), 999);
    journal.destroy().await.unwrap();
}

#[boxed]
async fn test_commit_handle_overlaps_predecessor_and_tail<F, Fut, J>(
    context: deterministic::Context,
    control: Arc<delayed_start_sync::Control>,
    make: F,
) where
    F: FnOnce(delayed_start_sync::Context) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: CommitHandle + 'static,
{
    let mut journal = make(delayed_start_sync::Context::new(
        context.child("a"),
        control.clone(),
    ))
    .await
    .unwrap();
    for i in 0..4u64 {
        journal.append(&i).await.unwrap();
    }
    let starts_before = control.starts();
    assert!(starts_before > 0);
    let waits_before = control.start_waits();

    let handle = journal.commit_handle().await;
    assert!(
        control.starts() > starts_before,
        "tail sync was not started while predecessor was in flight"
    );

    let waiter = context
        .child("commit")
        .spawn(|_| async move { handle.await.unwrap() });
    while control.start_waits() == waits_before {
        reschedule().await;
    }

    assert_eq!(
        control.start_completions(),
        0,
        "commit completed before predecessor was released"
    );

    control.release();
    waiter.await.unwrap();
    journal.destroy().await.unwrap();
}

/// A commit whose in-flight sync fails surfaces the error through both the returned handle and the
/// next durability operation.
#[boxed]
async fn test_commit_handle_failure_propagates<F, Fut, J>(
    context: deterministic::Context,
    control: Arc<delayed_start_sync::Control>,
    make: F,
) where
    F: FnOnce(delayed_start_sync::Context) -> Fut,
    Fut: Future<Output = Result<J, Error>>,
    J: CommitHandle,
{
    let mut journal = make(delayed_start_sync::Context::new(
        context.child("a"),
        control.clone(),
    ))
    .await
    .unwrap();
    for i in 0..4u64 {
        journal.append(&i).await.unwrap();
    }

    // Arm the in-flight sync to fail, and release it so it resolves to an error.
    control.arm_fail();
    control.release();

    let handle = journal.commit_handle().await;
    assert!(
        handle.await.is_err(),
        "the commit handle surfaces the failure"
    );
    assert!(
        matches!(Mutable::commit(&mut journal).await, Err(Error::Runtime(_))),
        "the next durability op surfaces the failed in-flight sync"
    );

    // A mutable method returned an error, so the journal is unusable per the failures-are-fatal
    // contract; just drop it.
    drop(journal);
}

fn fixed_overlap_cfg(context: &deterministic::Context, partition: &str) -> fixed::Config {
    fixed::Config {
        partition: partition.into(),
        items_per_blob: NZU64!(10),
        page_cache: CacheRef::from_pooler(context, NZU16!(44), NZUsize!(8)),
        write_buffer: NZUsize!(2048),
    }
}

fn variable_overlap_cfg(context: &deterministic::Context, partition: &str) -> variable::Config<()> {
    variable::Config {
        partition: partition.into(),
        items_per_section: NZU64!(10),
        compression: None,
        codec_config: (),
        page_cache: CacheRef::from_pooler(context, NZU16!(44), NZUsize!(8)),
        write_buffer: NZUsize!(2048),
    }
}

#[test]
fn test_fixed_commit_handle_overlaps_predecessor_and_tail() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let control = delayed_start_sync::Control::new();
        let cfg = fixed::Config {
            partition: "fixed-commit-handle-predecessor".into(),
            items_per_blob: NZU64!(3),
            page_cache: CacheRef::from_pooler(&context, NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
        };
        test_commit_handle_overlaps_predecessor_and_tail(context, control, move |ctx| {
            fixed::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_commit_handle_overlaps_predecessor_and_tail() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let control = delayed_start_sync::Control::new();
        let cfg = variable::Config {
            partition: "variable-commit-handle-predecessor".into(),
            items_per_section: NZU64!(3),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::from_pooler(&context, NZU16!(44), NZUsize!(8)),
            write_buffer: NZUsize!(2048),
        };
        test_commit_handle_overlaps_predecessor_and_tail(context, control, move |ctx| {
            variable::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_fixed_commit_handle_overlaps_work() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let control = delayed_start_sync::Control::new();
        let cfg = fixed_overlap_cfg(&context, "fixed-commit-handle-overlap");
        test_commit_handle_overlaps_work(context, control, move |ctx| {
            let cfg = cfg.clone();
            fixed::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_commit_handle_overlaps_work() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let control = delayed_start_sync::Control::new();
        let cfg = variable_overlap_cfg(&context, "variable-commit-handle-overlap");
        test_commit_handle_overlaps_work(context, control, move |ctx| {
            let cfg = cfg.clone();
            variable::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_fixed_commit_handle_failure_propagates() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let control = delayed_start_sync::Control::new();
        let cfg = fixed_overlap_cfg(&context, "fixed-commit-handle-fail");
        test_commit_handle_failure_propagates(context, control, move |ctx| {
            fixed::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}

#[test]
fn test_variable_commit_handle_failure_propagates() {
    let executor = deterministic::Runner::default();
    executor.start(|context| async move {
        let control = delayed_start_sync::Control::new();
        let cfg = variable_overlap_cfg(&context, "variable-commit-handle-fail");
        test_commit_handle_failure_propagates(context, control, move |ctx| {
            variable::Journal::<_, u64>::init(ctx, cfg)
        })
        .await;
    });
}
