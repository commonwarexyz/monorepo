//! Implementations of the `Storage` trait that can be used by the runtime.

use commonware_macros::stability_scope;

stability_scope!(BETA, cfg(not(target_arch = "wasm32")) {
    use crate::{BlobVersion, Error};
    use std::{
        collections::HashMap,
        fs::File,
        io::{Read as _, Seek as _, SeekFrom},
        ops::RangeInclusive,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };
    use ::tokio::sync::watch;
    use commonware_formatting::hex;
    #[cfg(test)]
    use crate::{Blob as _, BufferPool, ReadOptions, WriteOptions, buffer::Write};
    #[cfg(test)]
    use commonware_utils::NZUsize;
    #[cfg(test)]
    use std::time::Duration;
    #[cfg(test)]
    use ::tokio::time::timeout;

    /// Flush the whole filesystem containing `dir` at startup so that bytes a prior process wrote
    /// but did not `fsync` are crash-durable before any storage structure reads.
    ///
    /// Per-platform guarantee:
    /// - **Linux**: `syncfs(2)` makes all data on the storage filesystem crash-durable.
    /// - **macOS/BSD**: best-effort `sync(2)`; it does not flush the drive cache, so it is **not**
    ///   crash-durable.
    ///
    /// Assumes storage lives on a single filesystem; on Linux reliable error detection needs kernel
    /// >= 5.8.
    pub(crate) fn sync(dir: &std::path::Path) -> std::io::Result<()> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "linux")] {
                use std::os::fd::AsRawFd;
                let file = std::fs::File::open(dir)?;
                // SAFETY: `file` owns a valid fd that lives across the call; `syncfs` takes only
                // that fd, performs no memory access, and returns -1 on error.
                if unsafe { libc::syncfs(file.as_raw_fd()) } == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                tracing::debug!(
                    storage_directory = %dir.display(),
                    "made storage filesystem durable at startup (syncfs)"
                );
                Ok(())
            } else {
                // SAFETY: `sync` takes no arguments and cannot fail.
                unsafe { libc::sync() };
                tracing::debug!(
                    storage_directory = %dir.display(),
                    "best-effort storage flush at startup (sync(); not a crash-durability guarantee)"
                );
                Ok(())
            }
        }
    }

    /// Syncs a directory to ensure directory entry changes are durable.
    /// On Unix, directory metadata (file creation/deletion) must be explicitly fsynced.
    pub(crate) fn sync_dir(path: &Path) -> Result<(), Error> {
        let dir = File::open(path).map_err(|e| {
            Error::BlobOpenFailed(
                path.to_string_lossy().to_string(),
                "directory".to_string(),
                e.into(),
            )
        })?;
        dir.sync_all().map_err(|e| {
            Error::BlobSyncFailed(
                path.to_string_lossy().to_string(),
                "directory".to_string(),
                e.into(),
            )
        })
    }

    /// Deferred syncs and the live opens that can still register them.
    ///
    /// A name has at most one live open. Its identity binds registration to that open, while
    /// the receiver retains outstanding work and errors until the name is removed or recreated.
    #[derive(Default)]
    pub(crate) struct Pending {
        syncs: commonware_utils::sync::Mutex<HashMap<(String, Vec<u8>), Entry>>,
        #[cfg(test)]
        finished: AtomicU64,
        #[cfg(test)]
        deferred: commonware_utils::sync::Mutex<Vec<Receiver>>,
        #[cfg(test)]
        before_sync: commonware_utils::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        #[cfg(test)]
        fail_creation_after: commonware_utils::sync::Mutex<Option<usize>>,
    }

    #[derive(Default)]
    struct Entry {
        identity: std::sync::Weak<Generation>,
        sync: Option<Receiver>,
    }

    /// The live open of one namespace entry, dropped with the last handle of that open.
    pub(crate) struct Generation {
        pending: Arc<Pending>,
        key: (String, Vec<u8>),
    }

    impl Generation {
        /// Release the name for a later open, returning the sender that resolves the obligation
        /// every later open waits for. `None` once the name was removed or recreated, or while a
        /// retained failure still blocks it.
        pub(crate) fn release(&self) -> Option<Sender> {
            self.pending.start(self)
        }
    }

    impl Drop for Generation {
        fn drop(&mut self) {
            let mut syncs = self.pending.syncs.lock();
            if syncs.get(&self.key).is_some_and(|entry| {
                std::ptr::eq(entry.identity.as_ptr(), self) && entry.sync.is_none()
            }) {
                syncs.remove(&self.key);
            }
        }
    }

    /// The result of a pending sync, `None` while it runs.
    type Outcome = Option<Result<(), Error>>;
    type Receiver = watch::Receiver<Outcome>;
    pub(crate) type Sender = watch::Sender<Outcome>;

    impl Pending {
        /// Attach a fresh open to a name while the backend holds its namespace lock.
        ///
        /// # Panics
        ///
        /// Panics while a handle from an earlier open of the name is still alive.
        pub(crate) fn attach(
            self: &Arc<Self>,
            partition: &str,
            name: &[u8],
        ) -> (Arc<Generation>, Option<Receiver>) {
            let key = (partition.to_owned(), name.to_vec());
            let mut syncs = self.syncs.lock();
            let entry = syncs.entry(key.clone()).or_default();
            assert!(
                entry.identity.upgrade().is_none(),
                "blob {partition}/{} is already open",
                hex(name)
            );
            let generation = Arc::new(Generation { pending: self.clone(), key });
            entry.identity = Arc::downgrade(&generation);
            (generation, entry.sync.clone())
        }

        /// Register work only while this identity still owns its name and no earlier obligation
        /// is outstanding.
        fn start(&self, generation: &Generation) -> Option<Sender> {
            let mut syncs = self.syncs.lock();
            let entry = syncs.get_mut(&generation.key)?;
            if !std::ptr::eq(entry.identity.as_ptr(), generation) || entry.sync.is_some() {
                return None;
            }
            let (sender, receiver) = watch::channel(None);
            entry.sync = Some(receiver);
            Some(sender)
        }

        /// Publish a deferred sync's result, see [Self::resolve].
        fn finish(&self, key: &(String, Vec<u8>), sender: Sender, result: Result<(), Error>) {
            #[cfg(test)]
            if result.is_ok() {
                self.finished.fetch_add(1, Ordering::AcqRel);
            }
            self.resolve(key, sender, result);
        }

        /// Publish an obligation's result. A success releases its debt and a failure retains it.
        pub(crate) fn resolve(
            &self,
            key: &(String, Vec<u8>),
            sender: Sender,
            result: Result<(), Error>,
        ) {
            if result.is_ok() {
                let mut syncs = self.syncs.lock();
                if let Some(entry) = syncs.get_mut(key)
                    && entry.sync.as_ref().is_some_and(|receiver| receiver.same_channel(&sender.subscribe()))
                {
                    entry.sync = None;
                    if entry.identity.upgrade().is_none() {
                        syncs.remove(key);
                    }
                }
            }
            let _ = sender.send(Some(result));
        }

        /// Wait for the obligation captured when the file was opened.
        pub(crate) async fn wait(receiver: Option<Receiver>) -> Result<(), Error> {
            let Some(mut receiver) = receiver else {
                return Ok(());
            };
            receiver
                .wait_for(Option::is_some)
                .await
                .map_or(Err(Error::Closed), |outcome| {
                    outcome.clone().expect("outcome is published")
                })
        }

        /// Detach a removed name, or every name in a removed partition.
        pub(crate) fn forget(&self, partition: &str, name: Option<&[u8]>) {
            if let Some(name) = name {
                self.syncs.lock().remove(&(partition.to_owned(), name.to_vec()));
            } else {
                self.syncs.lock().retain(|(stored, _), _| {
                    stored != partition
                });
            }
        }

        /// Number of registered syncs.
        #[cfg(test)]
        pub(crate) fn len(&self) -> usize {
            self.syncs.lock().values().filter(|entry| entry.sync.is_some()).count()
        }

        /// Number of syncs that finished successfully.
        #[cfg(test)]
        pub(crate) fn finished(&self) -> u64 {
            self.finished.load(Ordering::Acquire)
        }
    }

    /// Tracks the writes to one blob file that no completed sync covers.
    ///
    /// Shared by every handle of one open, it counts mutations requiring a full-file barrier.
    /// Each sync credits only mutations completed before it began, so a mutation racing a sync
    /// stays dirty.
    #[derive(Default)]
    pub(crate) struct Tracker {
        written: AtomicU64,
        completed: AtomicU64,
        synced: AtomicU64,
        #[cfg(test)]
        skipped: AtomicU64,
    }

    impl Tracker {
        /// Record a mutation that needs a completed sync.
        pub(crate) fn write(&self) {
            self.written.fetch_add(1, Ordering::AcqRel);
        }

        /// Count a successful plain write or resize.
        pub(crate) fn complete(&self) {
            self.completed.fetch_add(1, Ordering::AcqRel);
        }

        /// Observe the completed writes a sync about to be issued will cover.
        pub(crate) fn begin_sync(&self) -> u64 {
            self.completed.load(Ordering::Acquire)
        }

        /// Credit a completed sync with the writes observed when it began.
        pub(crate) fn end_sync(&self, seen: u64) {
            self.synced.fetch_max(seen, Ordering::AcqRel);
        }

        /// Whether writes were issued that no completed sync covers.
        pub(crate) fn is_dirty(&self) -> bool {
            self.written.load(Ordering::Acquire) != self.synced.load(Ordering::Acquire)
        }

        /// Record a sync that found nothing to persist. Callers sync freely and the runtime
        /// skips the device flush when every mutation through the open is already covered.
        #[cfg(test)]
        pub(crate) fn skip_sync(&self) {
            self.skipped.fetch_add(1, Ordering::AcqRel);
        }

        /// Number of syncs skipped because the open was clean.
        #[cfg(test)]
        pub(crate) fn skipped(&self) -> u64 {
            self.skipped.load(Ordering::Acquire)
        }
    }

    /// Run a deferred sync for a blob whose open ended dirty, resolving its obligation with
    /// `sender`.
    ///
    /// The sync runs on the blocking pool when a runtime is available and inline otherwise. A
    /// pool that is shutting down may discard queued work, so a blob dropped dirty during runtime
    /// teardown relies on the next start's flush. `sync` must own everything the sync needs,
    /// including the directory hold.
    pub(crate) fn defer_sync(
        pending: Arc<Pending>,
        key: (String, Vec<u8>),
        sender: Sender,
        sync: impl FnOnce() -> Result<(), Error> + Send + 'static,
    ) {
        #[cfg(test)]
        let gate = {
            pending.deferred.lock().push(sender.subscribe());
            pending.before_sync.lock().take()
        };
        let work = move || {
            #[cfg(test)]
            if let Some(gate) = gate {
                let _ = gate.recv();
            }
            let result = sync();
            pending.finish(&key, sender, result);
        };
        match ::tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn_blocking(work);
            }
            Err(_) => work(),
        }
    }

    #[cfg(test)]
    pub(crate) async fn check_failed_creation<S: crate::Storage>(storage: &S, pending: &Pending) {
        for partial in [true, false] {
            *pending.fail_creation_after.lock() = Some(if partial { 1 } else { usize::MAX });
            assert!(matches!(storage.open("failed_creation", b"blob").await, Err(Error::Closed)));
            if !partial {
                for _ in 0..2 {
                    assert!(matches!(storage.open("failed_creation", b"blob").await, Err(Error::Closed)),
                        "a parseable header must not hide the failed creation barrier");
                }
                storage.remove("failed_creation", Some(b"blob")).await.unwrap();
            }
            let (blob, size) = storage.open("failed_creation", b"blob").await.unwrap();
            assert_eq!(size, 0);
            drop(blob);
            storage.remove("failed_creation", None).await.unwrap();
        }
        assert!(pending.deferred.lock().is_empty(), "failed creation must not launch a sync job");
    }

    #[cfg(test)]
    pub(crate) async fn check_remove_live_dirty_owner<S: crate::Storage>(
        storage: &S,
        pending: &Pending,
        pool: &BufferPool,
    ) {
        for by_name in [true, false] {
            for unlink_first in [false, true] {
                let partition = "remove_live_dirty";
                let name = b"blob";
                let (blob, size) = storage.open(partition, name).await.unwrap();
                let mut writer = Write::new(blob, size, NZUsize!(1), pool.clone());
                writer.write_at(0, b"dirty").await.unwrap();
                writer.wait_for_sync().await.unwrap();
                let before = pending.deferred.lock().len();
                let finished = pending.finished();
                let target = by_name.then_some(name.as_slice());

                if unlink_first {
                    storage.remove(partition, target).await.unwrap();
                    assert_eq!(
                        writer.read_at(0, 5).await.unwrap().coalesce().as_ref(),
                        b"dirty",
                    );
                    drop(writer);
                } else {
                    drop(writer);
                    storage.remove(partition, target).await.unwrap();
                }

                let jobs = pending.deferred.lock()[before..].to_vec();
                assert_eq!(jobs.len(), usize::from(!unlink_first));
                for mut job in jobs {
                    timeout(Duration::from_secs(10), job.wait_for(Option::is_some))
                        .await.unwrap().unwrap().clone().unwrap().unwrap();
                }
                assert_eq!(pending.finished() - finished, u64::from(!unlink_first));
                if by_name {
                    storage.remove(partition, None).await.unwrap();
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn check_sync_writes<S: crate::Storage>(storage: &S, pending: &Pending) {
        for (case, options) in [WriteOptions::SYNC, WriteOptions::SYNC | WriteOptions::DONT_CACHE].into_iter().enumerate() {
            let before = pending.finished();
            let (blob, _) = storage.open("durable_writes", &[case as u8]).await.unwrap();
            blob.write_at(0, b"first", options).await.unwrap();
            blob.write_at(5, b"second", options).await.unwrap();
            drop(blob);
            let (blob, size) = storage.open("durable_writes", &[case as u8]).await.unwrap();
            assert_eq!(size, 11);
            assert_eq!(blob.read_at(0, 11, ReadOptions::default()).await.unwrap().coalesce().as_ref(), b"firstsecond");
            drop(blob);
            assert_eq!(pending.finished(), before, "successful durable writes need no reopen sync");
        }

        for plain_first in [false, true] {
            let before = pending.finished();
            let name = if plain_first { b"prior".as_slice() } else { b"later".as_slice() };
            let (blob, _) = storage.open("durable_writes", name).await.unwrap();
            let (first, second) = if plain_first {
                (WriteOptions::default(), WriteOptions::SYNC)
            } else {
                (WriteOptions::SYNC, WriteOptions::default())
            };
            blob.write_at(0, b"first", first).await.unwrap();
            blob.write_at(5, b"second", second).await.unwrap();
            drop(blob);
            let (blob, size) = storage.open("durable_writes", name).await.unwrap();
            assert_eq!(size, 11);
            assert_eq!(blob.read_at(0, 11, ReadOptions::default()).await.unwrap().coalesce().as_ref(), b"firstsecond");
            drop(blob);
            let needs_sync = !plain_first || cfg!(target_os = "linux");
            assert_eq!(pending.finished() - before, u64::from(needs_sync));
        }
    }

    #[cfg(test)]
    pub(crate) async fn check_recreate_reopen<S: crate::Storage>(storage: &S, pending: &Pending) {
        drop(storage.open("independent", b"ready").await.unwrap());
        for remove_name in [true, false] {
            let partition = "recreate_pending";
            let name = b"blob";
            let (old, _) = storage.open(partition, name).await.unwrap();
            old.write_at(0, b"old", WriteOptions::default()).await.unwrap();
            storage.remove(partition, remove_name.then_some(name.as_slice())).await.unwrap();
            assert_eq!(old.read_at(0, 3, ReadOptions::default()).await.unwrap().coalesce().as_ref(), b"old");

            let (current, len) = storage.open(partition, name).await.unwrap();
            assert_eq!(len, 0);
            let reader = current.clone();
            current.write_at(0, b"new", WriteOptions::default()).await.unwrap();

            // Dropping the sender also releases the worker if an assertion unwinds.
            let (release, gate) = std::sync::mpsc::channel();
            pending.deferred.lock().clear();
            *pending.before_sync.lock() = Some(gate);
            drop(current);
            drop(old);
            drop(reader);
            let jobs = pending.deferred.lock().clone();
            if let Some(mut obsolete) = jobs.get(1).cloned() {
                timeout(Duration::from_secs(10), obsolete.wait_for(Option::is_some))
                    .await.unwrap().unwrap().clone().unwrap().unwrap();
            }

            let mut reopen = Box::pin(storage.open(partition, name));
            let early = timeout(Duration::from_millis(50), &mut reopen).await;
            let completed_early = early.is_ok();
            let clean_progress = timeout(Duration::from_secs(5), async {
                let names = storage.scan("independent").await?;
                let (blob, len) = storage.open("independent", b"ready").await?;
                drop(blob);
                Ok::<_, Error>((names, len))
            }).await;
            drop(release);
            let (reopened, len) = match early {
                Ok(result) => result,
                Err(_) => reopen.await,
            }.unwrap();
            let bytes = reopened.read_at(0, 3, ReadOptions::default()).await.unwrap().coalesce();
            drop(reopened);
            storage.remove(partition, None).await.unwrap();
            assert_eq!(len, 3);
            assert_eq!(bytes.as_ref(), b"new");
            assert!(!completed_early, "reopen exposed the replacement before its deferred sync");
            let (names, len) = clean_progress.expect("a dirty sync blocked another partition").unwrap();
            assert_eq!(names, vec![b"ready".to_vec()]);
            assert_eq!(len, 0);
        }
    }

    /// Reads a blob's leading bytes and resolves its header (see [header::resolve]).
    pub(crate) fn resolve_header(
        file: &mut File,
        raw_len: u64,
        layouts: &RangeInclusive<Layout>,
        versions: &RangeInclusive<BlobVersion>,
        partition: &str,
        name: &[u8],
    ) -> Result<Option<(u64, BlobVersion, u64)>, Error> {
        let mut raw = vec![0u8; Header::resolve_len(raw_len)];
        file.seek(SeekFrom::Start(0))
            .map_err(|_| Error::ReadFailed)?;
        file.read_exact(&mut raw).map_err(|_| Error::ReadFailed)?;
        header::resolve(&raw, raw_len, layouts, versions, partition, name)
    }

    pub(crate) mod hold;
});

stability_scope!(ALPHA {
    pub mod audited;
    pub mod faulty;
    pub mod memory;
});
stability_scope!(ALPHA, cfg(feature = "iouring-storage") {
    pub mod iouring;
});
stability_scope!(BETA, cfg(all(not(target_arch = "wasm32"), not(feature = "iouring-storage"))) {
    pub mod tokio;
});
stability_scope!(BETA {
    pub mod metered;

    mod header;
    pub(crate) use crate::BlobLayout as Layout;
    pub(crate) use header::Header;

    /// Validate that a partition name contains only allowed characters.
    ///
    /// Partition names must only contain alphanumeric characters, dashes ('-'),
    /// or underscores ('_').
    pub fn validate_partition_name(partition: &str) -> Result<(), crate::Error> {
        if partition.is_empty()
            || partition
                .chars()
                .any(|c| !(c.is_ascii_alphanumeric() || ['_', '-'].contains(&c)))
        {
            return Err(crate::Error::PartitionNameInvalid(partition.into()));
        }
        Ok(())
    }
});

#[cfg(test)]
pub(crate) mod tests {
    pub(crate) use super::header::tests::v0_blob_bytes;
    use crate::{
        Blob, BlobVersion, Buf, IoBuf, IoBufMut, IoBufs, IoBufsMut, ReadOptions, Storage,
        WriteOptions,
    };
    use futures::FutureExt;

    #[cfg(not(target_arch = "wasm32"))]
    mod tracker {
        use crate::{
            Error,
            storage::{Pending, Tracker, defer_sync},
        };
        use std::sync::Arc;

        #[test]
        fn test_synced_writes_are_clean() {
            let tracker = Tracker::default();
            assert!(!tracker.is_dirty());
            tracker.write();
            assert!(tracker.is_dirty());
            tracker.complete();
            let seen = tracker.begin_sync();
            tracker.end_sync(seen);
            assert!(!tracker.is_dirty());
        }

        #[test]
        fn test_unlanded_write_is_not_credited() {
            let tracker = Tracker::default();
            tracker.write();

            // The sync began before the write reached the file, so it cannot cover it.
            let seen = tracker.begin_sync();
            tracker.complete();
            tracker.end_sync(seen);
            assert!(tracker.is_dirty());
            let later = tracker.begin_sync();
            tracker.end_sync(later);
            assert!(!tracker.is_dirty());
        }

        #[test]
        fn test_write_racing_sync_stays_dirty() {
            let tracker = Tracker::default();
            tracker.write();
            tracker.complete();
            let seen = tracker.begin_sync();
            tracker.write();
            tracker.complete();
            tracker.end_sync(seen);
            assert!(tracker.is_dirty());

            // A sync observing both writes clears the state, and a stale completion
            // cannot regress it.
            let later = tracker.begin_sync();
            tracker.end_sync(later);
            tracker.end_sync(seen);
            assert!(!tracker.is_dirty());
        }

        fn key() -> (String, Vec<u8>) {
            ("a".to_owned(), b"1".to_vec())
        }

        #[tokio::test]
        async fn test_wait_observes_pending_sync() {
            let pending = Arc::new(Pending::default());
            let (generation, wait) = pending.attach("a", b"1");
            Pending::wait(wait).await.unwrap();
            let sender = generation.release().unwrap();
            drop(generation);
            let (generation, wait) = pending.attach("a", b"1");
            let waiter = tokio::spawn(Pending::wait(wait));
            tokio::task::yield_now().await;
            assert!(!waiter.is_finished());
            pending.finish(&key(), sender, Ok(()));
            waiter.await.unwrap().unwrap();
            assert_eq!(pending.len(), 0);
            assert_eq!(pending.finished(), 1);
            drop(generation);
            assert!(pending.syncs.lock().is_empty());
        }

        #[tokio::test]
        async fn test_failed_sync_stays_until_forgotten() {
            let pending = Arc::new(Pending::default());
            let (generation, _) = pending.attach("a", b"1");
            let sender = generation.release().unwrap();
            pending.finish(&key(), sender, Err(Error::Closed));
            drop(generation);
            for _ in 0..2 {
                let (generation, wait) = pending.attach("a", b"1");
                assert!(matches!(Pending::wait(wait).await, Err(Error::Closed)));
                // A failed open cannot replace the retained failure with its own release.
                assert!(generation.release().is_none());
                drop(generation);
                assert_eq!(pending.len(), 1);
            }
            pending.forget("a", Some(b"1"));
            let (generation, wait) = pending.attach("a", b"1");
            Pending::wait(wait).await.unwrap();
            drop(generation);
            assert!(pending.syncs.lock().is_empty());
        }

        #[test]
        fn test_live_open_refuses_a_second_attach() {
            let pending = Arc::new(Pending::default());
            let (first, _) = pending.attach("a", b"1");
            let second = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                pending.attach("a", b"1")
            }));
            assert!(second.is_err(), "a live open must refuse a second open");
            drop(first);
            drop(pending.attach("a", b"1"));
        }

        #[test]
        fn test_generations_retire_and_release_clean_entries() {
            let pending = Arc::new(Pending::default());
            let (first, _) = pending.attach("a", b"1");
            let sender = first.release().unwrap();
            drop(first);
            assert_eq!(pending.syncs.lock().len(), 1);
            pending.finish(&key(), sender, Ok(()));
            assert!(pending.syncs.lock().is_empty());

            for name in 0..128u64 {
                drop(pending.attach("clean", &name.to_be_bytes()));
                assert!(pending.syncs.lock().is_empty());
            }

            let (old, _) = pending.attach("a", b"1");
            pending.forget("a", Some(b"1"));
            let (current, _) = pending.attach("a", b"1");
            let current_sync = current.release().unwrap();
            assert!(old.release().is_none());
            drop(old);
            assert_eq!(pending.len(), 1);
            drop(current);
            assert_eq!(pending.len(), 1);
            pending.finish(&key(), current_sync, Ok(()));
            assert!(pending.syncs.lock().is_empty());
        }

        #[tokio::test]
        async fn test_defer_sync_runs_on_the_blocking_pool() {
            let pending = Arc::new(Pending::default());
            let (generation, _) = pending.attach("a", b"1");
            let sender = generation.release().unwrap();
            drop(generation);
            defer_sync(pending.clone(), key(), sender, || Ok(()));
            Pending::wait(pending.attach("a", b"1").1).await.unwrap();
            assert_eq!(pending.finished(), 1);
            assert_eq!(pending.len(), 0);
        }

        #[test]
        fn test_defer_sync_runs_inline_without_a_runtime() {
            let pending = Arc::new(Pending::default());
            let (generation, _) = pending.attach("a", b"1");
            let sender = generation.release().unwrap();
            drop(generation);
            defer_sync(pending.clone(), key(), sender, || Ok(()));
            assert_eq!(pending.finished(), 1);
            assert!(pending.syncs.lock().is_empty());
        }
    }

    /// Runs the full suite of tests on the provided storage implementation.
    pub(crate) async fn run_storage_tests<S>(storage: S)
    where
        S: Storage + Send + Sync + 'static,
        S::Blob: Send + Sync,
    {
        test_open_and_write(&storage).await;
        test_remove(&storage).await;
        test_read_after_remove_blob(&storage).await;
        test_read_after_remove_partition(&storage).await;
        test_recreate_after_remove(&storage).await;
        test_read_after_remove_unsynced(&storage).await;
        test_read_after_remove_handle_clones(&storage).await;
        test_recreate_generations(&storage).await;
        test_read_after_remove_partition_multi(&storage).await;
        test_scan(&storage).await;
        test_concurrent_access(&storage).await;
        test_large_data(&storage).await;
        test_overwrite_data(&storage).await;
        test_read_beyond_bound(&storage).await;
        test_write_at_large_offset(&storage).await;
        test_write_at_sync(&storage).await;
        test_start_sync(&storage).await;
        test_append_data(&storage).await;
        test_vectored_write_at(&storage).await;
        test_vectored_write_at_large_offset(&storage).await;
        test_sequential_read_write(&storage).await;
        test_sequential_chunk_read_write(&storage).await;
        test_read_empty_blob(&storage).await;
        test_overlapping_writes(&storage).await;
        test_resize_then_open(&storage).await;
        test_partition_name_validation(&storage).await;
        test_blob_version_mismatch(&storage).await;
        test_aligned_layout(&storage).await;
        test_read_zero_length(&storage).await;
        test_read_at_buf_returns_same_buffer(&storage).await;
        test_read_at_buf_insufficient_capacity(&storage).await;
        test_read_at_buf_larger_capacity(&storage).await;
        test_read_options(&storage).await;
    }

    /// Test opening a blob, writing to it, and reading back the data.
    async fn test_open_and_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, len) = storage.open("partition", b"test_blob").await.unwrap();
        assert_eq!(len, 0);

        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();
        let read = blob.read_at(0, 11, ReadOptions::default()).await.unwrap();

        assert_eq!(
            read.coalesce(),
            b"hello world",
            "Blob content does not match expected value"
        );
    }

    /// Test removing a blob from storage.
    async fn test_remove<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        storage.open("partition", b"test_blob").await.unwrap();
        storage
            .remove("partition", Some(b"test_blob"))
            .await
            .unwrap();

        let blobs = storage.scan("partition").await.unwrap();
        assert!(blobs.is_empty(), "Blob was not removed as expected");
    }

    /// An already-open handle remains fully readable after the blob is removed by name.
    async fn test_read_after_remove_blob<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("read_after_remove", b"by_name").await.unwrap();
        let data: Vec<u8> = (0u8..=255).collect();
        blob.write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        storage
            .remove("read_after_remove", Some(b"by_name"))
            .await
            .unwrap();

        // The name is gone but the open handle keeps reading the removed blob's bytes.
        let blobs = storage.scan("read_after_remove").await.unwrap();
        assert!(blobs.is_empty(), "Blob was not removed as expected");
        let read = blob
            .read_at(0, data.len(), ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            data.as_slice(),
            "open handle must remain readable after blob removal"
        );
    }

    /// An already-open handle remains fully readable after its entire partition is removed.
    async fn test_read_after_remove_partition<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("read_after_remove_partition", b"victim")
            .await
            .unwrap();
        let data: Vec<u8> = (0u8..=255).rev().collect();
        blob.write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();

        storage
            .remove("read_after_remove_partition", None)
            .await
            .unwrap();

        let read = blob
            .read_at(0, data.len(), ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            data.as_slice(),
            "open handle must remain readable after partition removal"
        );
    }

    /// Re-opening a removed blob's name creates an independent blob; the pre-removal handle keeps
    /// observing the removed blob's contents.
    async fn test_recreate_after_remove<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (old, _) = storage
            .open("recreate_after_remove", b"name")
            .await
            .unwrap();
        old.write_at(0, b"old contents", WriteOptions::default())
            .await
            .unwrap();
        old.sync().await.unwrap();

        storage
            .remove("recreate_after_remove", Some(b"name"))
            .await
            .unwrap();

        // Re-creating the name yields a fresh, empty, independent blob.
        let (new, len) = storage
            .open("recreate_after_remove", b"name")
            .await
            .unwrap();
        assert_eq!(len, 0, "recreated blob must start empty");
        new.write_at(0, b"new contents", WriteOptions::default())
            .await
            .unwrap();
        new.sync().await.unwrap();

        let old_read = old.read_at(0, 12, ReadOptions::default()).await.unwrap();
        assert_eq!(
            old_read.coalesce().as_ref(),
            b"old contents",
            "pre-removal handle must keep observing the removed blob"
        );
        let new_read = new.read_at(0, 12, ReadOptions::default()).await.unwrap();
        assert_eq!(new_read.coalesce().as_ref(), b"new contents");
    }

    /// Bytes written but never synced remain readable through an open handle after removal.
    async fn test_read_after_remove_unsynced<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("read_after_remove_unsynced", b"name")
            .await
            .unwrap();
        let data: Vec<u8> = (0u8..=255).cycle().take(64 * 1024).collect();
        blob.write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();

        // Read through the handle before removal so the removal crosses an actively-used handle.
        let read = blob.read_at(0, 16, ReadOptions::default()).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), &data[..16]);

        storage
            .remove("read_after_remove_unsynced", Some(b"name"))
            .await
            .unwrap();

        // Unsynced bytes are still served in full.
        let read = blob
            .read_at(0, data.len(), ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            data.as_slice(),
            "unsynced bytes must remain readable after removal"
        );
        let read = blob
            .read_at(data.len() as u64 - 1, 1, ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(read.coalesce().as_ref(), &data[data.len() - 1..]);
    }

    /// Removal liveness is per-open, not per-handle: clones taken before or after removal keep
    /// reading regardless of other handles' lifetimes, and out-of-bounds reads still fail.
    async fn test_read_after_remove_handle_clones<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (first, _) = storage
            .open("read_after_remove_clones", b"name")
            .await
            .unwrap();
        let data: Vec<u8> = (0u8..=255).collect();
        first
            .write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();
        first.sync().await.unwrap();
        let second = first.clone();

        storage
            .remove("read_after_remove_clones", Some(b"name"))
            .await
            .unwrap();

        // A clone taken after removal reads too, and outlives the handle it was cloned from.
        let third = first.clone();
        drop(first);

        for handle in [&second, &third] {
            let read = handle
                .read_at(0, data.len(), ReadOptions::default())
                .await
                .unwrap();
            assert_eq!(read.coalesce().as_ref(), data.as_slice());
            assert!(
                handle
                    .read_at(data.len() as u64, 1, ReadOptions::default())
                    .await
                    .is_err(),
                "out-of-bounds read must still fail after removal"
            );
        }
    }

    /// Every removed generation of a name stays readable through its own handle while the name
    /// is recreated and removed repeatedly.
    async fn test_recreate_generations<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let partition = "recreate_generations";

        // Hold a handle on each of three generations of the same name, each removed while open.
        let mut handles = Vec::new();
        for generation in 0u8..3 {
            let (blob, len) = storage.open(partition, b"name").await.unwrap();
            assert_eq!(len, 0, "each recreation must start empty");
            let data = vec![generation; 32];
            blob.write_at(0, data.clone(), WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            storage.remove(partition, Some(b"name")).await.unwrap();
            handles.push((blob, data));
        }

        // Churn the name further with the removed generations still held.
        for _ in 0..5 {
            let (blob, _) = storage.open(partition, b"name").await.unwrap();
            blob.write_at(0, vec![0xFF; 8], WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            drop(blob);
            storage.remove(partition, Some(b"name")).await.unwrap();
        }

        for (blob, data) in &handles {
            let read = blob
                .read_at(0, data.len(), ReadOptions::default())
                .await
                .unwrap();
            assert_eq!(
                read.coalesce().as_ref(),
                data.as_slice(),
                "each handle must keep observing its own generation"
            );
        }
    }

    /// Every handle into a removed partition stays readable, including a large blob at interior
    /// offsets, and recreating the partition yields independent blobs.
    async fn test_read_after_remove_partition_multi<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let partition = "read_after_remove_partition_multi";
        let (small_a, _) = storage.open(partition, b"a").await.unwrap();
        small_a
            .write_at(0, b"alpha", WriteOptions::default())
            .await
            .unwrap();
        small_a.sync().await.unwrap();
        // Deliberately never synced: partition removal must not lose unsynced bytes either.
        let (small_b, _) = storage.open(partition, b"b").await.unwrap();
        small_b
            .write_at(0, b"bravo", WriteOptions::default())
            .await
            .unwrap();

        const LARGE_LEN: usize = 1 << 20;
        let (large, _) = storage.open(partition, b"large").await.unwrap();
        let data: Vec<u8> = (0u8..=255).cycle().take(LARGE_LEN).collect();
        large
            .write_at(0, data.clone(), WriteOptions::default())
            .await
            .unwrap();
        large.sync().await.unwrap();

        storage.remove(partition, None).await.unwrap();

        let read = small_a.read_at(0, 5, ReadOptions::default()).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), b"alpha");
        let read = small_b.read_at(0, 5, ReadOptions::default()).await.unwrap();
        assert_eq!(read.coalesce().as_ref(), b"bravo");

        // Start, unaligned interior, and final-byte reads of the large blob.
        for (offset, len) in [(0usize, 4096), (123_457, 8192), (LARGE_LEN - 1, 1)] {
            let read = large
                .read_at(offset as u64, len, ReadOptions::default())
                .await
                .unwrap();
            assert_eq!(
                read.coalesce().as_ref(),
                &data[offset..offset + len],
                "offset={offset} len={len}"
            );
        }

        // Recreating the partition and a same-named blob yields an independent blob.
        let (fresh, len) = storage.open(partition, b"a").await.unwrap();
        assert_eq!(len, 0, "recreated blob must start empty");
        fresh
            .write_at(0, b"fresh", WriteOptions::default())
            .await
            .unwrap();
        fresh.sync().await.unwrap();
        let read = small_a.read_at(0, 5, ReadOptions::default()).await.unwrap();
        assert_eq!(
            read.coalesce().as_ref(),
            b"alpha",
            "pre-removal handle must keep observing the removed partition's blob"
        );
    }

    /// Test scanning a partition for blobs.
    async fn test_scan<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        storage.open("partition", b"blob1").await.unwrap();
        storage.open("partition", b"blob2").await.unwrap();

        let blobs = storage.scan("partition").await.unwrap();
        assert_eq!(
            blobs.len(),
            2,
            "Scan did not return the expected number of blobs"
        );
        assert!(
            blobs.contains(&b"blob1".to_vec()),
            "Blob1 is missing from scan results"
        );
        assert!(
            blobs.contains(&b"blob2".to_vec()),
            "Blob2 is missing from scan results"
        );
    }

    /// Test concurrent access to the same blob.
    async fn test_concurrent_access<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Initialize blob with data of sufficient length first
        blob.write_at(0, b"concurrent write", WriteOptions::default())
            .await
            .unwrap();

        // Read and write concurrently
        let write_task = tokio::spawn({
            let blob = blob.clone();
            async move {
                blob.write_at(0, IoBuf::from(b"concurrent write"), WriteOptions::default())
                    .await
                    .unwrap();
            }
        });

        let read_task = tokio::spawn({
            let blob = blob.clone();
            async move { blob.read_at(0, 16, ReadOptions::default()).await.unwrap() }
        });

        write_task.await.unwrap();
        let buffer = read_task.await.unwrap();

        assert_eq!(
            buffer.coalesce(),
            b"concurrent write",
            "Concurrent access failed"
        );
    }

    /// Test handling of large data sizes.
    async fn test_large_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"large_blob").await.unwrap();

        let large_data = vec![42u8; 10 * 1024 * 1024]; // 10 MB
        blob.write_at(0, large_data.clone(), WriteOptions::default())
            .await
            .unwrap();

        let read = blob
            .read_at(0, 10 * 1024 * 1024, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();

        assert_eq!(read, large_data.as_slice(), "Large data read/write failed");
    }

    /// Test overwriting data in a blob.
    async fn test_overwrite_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_overwrite_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(0, b"initial data", WriteOptions::default())
            .await
            .unwrap();

        // Overwrite part of the data
        blob.write_at(8, b"overwrite", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob
            .read_at(0, 17, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();

        assert_eq!(
            read, b"initial overwrite",
            "Data was not overwritten correctly"
        );
    }

    /// Test reading from an offset beyond the written data.
    async fn test_read_beyond_bound<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_beyond_written_data", b"test_blob")
            .await
            .unwrap();

        // Write some data
        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();

        // Attempt to read beyond the written data
        let result = blob.read_at(6, 10, ReadOptions::default()).await;
        assert!(
            result.is_err(),
            "Reading beyond written data should return an error"
        );

        // Same check via read_at_buf
        let buf = IoBufMut::with_capacity(10);
        let result = blob.read_at_buf(6, 10, buf, ReadOptions::default()).await;
        assert!(
            result.is_err(),
            "read_at_buf beyond written data should return an error"
        );
    }

    /// Test writing data at a large offset.
    async fn test_write_at_large_offset<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_write_at_large_offset", b"test_blob")
            .await
            .unwrap();

        // Write data at a large offset
        blob.write_at(10_000, b"offset data", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob
            .read_at(10_000, 11, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read, b"offset data", "Data at large offset is incorrect");
    }

    /// Test writing and syncing data in one operation.
    async fn test_write_at_sync<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_write_at_sync", b"test_blob")
            .await
            .unwrap();

        // Empty writes should be accepted without extending the blob.
        blob.write_at(1024, Vec::<u8>::new(), WriteOptions::SYNC)
            .await
            .unwrap();
        drop(blob);

        let (blob, len) = storage
            .open("test_write_at_sync", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 0);

        // Non-empty writes must be visible after reopen without a separate sync call.
        blob.write_at(0, b"hello", WriteOptions::SYNC)
            .await
            .unwrap();
        blob.write_at(
            5,
            vec![IoBuf::from(b" "), IoBuf::from(b"world")],
            WriteOptions::SYNC,
        )
        .await
        .unwrap();
        drop(blob);

        // Reopening a blob in the same process may still observe dirty kernel
        // page-cache state, so this doesn't really prove write durability.
        let (blob, len) = storage
            .open("test_write_at_sync", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 11);
        let read = blob
            .read_at(0, 11, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    /// Test that `start_sync` durably persists data, matching `sync`.
    async fn test_start_sync<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, len) = storage.open("test_start_sync", b"test_blob").await.unwrap();
        assert_eq!(len, 0);

        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();
        blob.start_sync().await.await.unwrap();
        drop(blob);

        // The bytes must survive a reopen, just as they would after `sync`.
        let (blob, len) = storage.open("test_start_sync", b"test_blob").await.unwrap();
        assert_eq!(len, 11);
        let read = blob
            .read_at(0, 11, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read.as_ref(), b"hello world");
    }

    /// Test appending data to a blob.
    async fn test_append_data<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_append_data", b"test_blob")
            .await
            .unwrap();

        // Write initial data
        blob.write_at(0, b"first", WriteOptions::default())
            .await
            .unwrap();

        // Append data
        blob.write_at(5, b"second", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob
            .read_at(0, 11, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read, b"firstsecond", "Appended data is incorrect");
    }

    /// Test vectored writes at offset 0.
    async fn test_vectored_write_at<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let test = |partition, bufs: Vec<IoBuf>, options, context| async move {
            // Coalesce the input to test later when reading
            let expected = IoBufs::from(bufs.clone()).coalesce();
            let (blob, _) = storage.open(partition, b"test_blob").await.unwrap();

            // Write data
            blob.write_at(0, bufs, options).await.unwrap();

            // Read back the data
            let read = blob
                .read_at(0, expected.len(), ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read.as_ref(), expected.as_ref(), "{context}");
        };

        test(
            "test_vectored_write_basic",
            vec![
                IoBuf::from(b"hello"),
                IoBuf::from(b" "),
                IoBuf::from(b"world"),
            ],
            WriteOptions::default(),
            "Vectored write content is incorrect",
        )
        .await;

        test(
            "test_vectored_write_empty_chunks",
            vec![
                IoBuf::default(),
                IoBuf::from(b"abc"),
                IoBuf::default(),
                IoBuf::from(b"def"),
                IoBuf::default(),
            ],
            WriteOptions::default(),
            "Vectored write with empties is incorrect",
        )
        .await;

        // Both filesystem backends cap one submission at 1,024 iovecs.
        let chunk_count = 1_025;
        let mut bufs = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            bufs.push(IoBuf::from(vec![i as u8]));
        }

        test(
            "test_vectored_write_many_chunks",
            bufs.clone(),
            WriteOptions::default(),
            "Vectored write over batch size is incorrect",
        )
        .await;
        test(
            "test_vectored_sync_write_many_chunks",
            bufs,
            WriteOptions::SYNC,
            "Synchronized vectored write over batch size is incorrect",
        )
        .await;
    }

    /// Test vectored writes at large offset with many chunks.
    async fn test_vectored_write_at_large_offset<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_vectored_write_at_large_offset", b"test_blob")
            .await
            .unwrap();

        let chunk_count = 128;
        let mut bufs = Vec::with_capacity(chunk_count);
        for i in 0..chunk_count {
            bufs.push(IoBuf::from(vec![i as u8; i]));
        }
        let expected = IoBufs::from(bufs.clone()).coalesce();

        // Write vectored data at a large offset
        blob.write_at(5_000, bufs, WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob
            .read_at(5_000, expected.len(), ReadOptions::default())
            .await
            .unwrap()
            .coalesce();

        assert_eq!(
            read.as_ref(),
            expected.as_ref(),
            "Vectored write at offset content is incorrect"
        );

        // Prefix gap should be zero-filled.
        let prefix = blob
            .read_at(0, 5_000, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(prefix.as_ref(), [0u8; 5_000]);
    }

    /// Test reading and writing with interleaved offsets.
    async fn test_sequential_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("partition", b"test_blob").await.unwrap();

        // Write data at different offsets
        blob.write_at(0, b"first", WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(10, b"second", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob
            .read_at(0, 5, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read, b"first", "Data at offset 0 is incorrect");

        let read = blob
            .read_at(10, 6, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read, b"second", "Data at offset 10 is incorrect");
    }

    /// Test writing and reading large data in chunks.
    async fn test_sequential_chunk_read_write<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_large_data_in_chunks", b"large_blob")
            .await
            .unwrap();

        let chunk_size = 1024 * 1024; // 1 MB
        let num_chunks = 10;
        let data = vec![7u8; chunk_size];

        // Write data in chunks
        for i in 0..num_chunks {
            blob.write_at(
                (i * chunk_size) as u64,
                data.clone(),
                WriteOptions::default(),
            )
            .await
            .unwrap();
        }

        // Read back the data in chunks
        for i in 0..num_chunks {
            let read = blob
                .read_at((i * chunk_size) as u64, chunk_size, ReadOptions::default())
                .await
                .unwrap()
                .coalesce();
            assert_eq!(read, data.as_slice(), "Chunk {i} is incorrect");
        }
    }

    /// Test reading from an empty blob.
    async fn test_read_empty_blob<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_empty_blob", b"empty_blob")
            .await
            .unwrap();

        let result = blob.read_at(0, 1, ReadOptions::default()).await;
        assert!(
            result.is_err(),
            "Reading from an empty blob should return an error"
        );

        // Same check via read_at_buf
        let buf = IoBufMut::with_capacity(1);
        let result = blob.read_at_buf(0, 1, buf, ReadOptions::default()).await;
        assert!(
            result.is_err(),
            "read_at_buf from an empty blob should return an error"
        );
    }

    /// Test writing and reading with overlapping writes.
    async fn test_overlapping_writes<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_overlapping_writes", b"test_blob")
            .await
            .unwrap();

        // Write overlapping data
        blob.write_at(0, b"overlap", WriteOptions::default())
            .await
            .unwrap();
        blob.write_at(4, b"map", WriteOptions::default())
            .await
            .unwrap();

        // Read back the data
        let read = blob
            .read_at(0, 7, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read, b"overmap", "Overlapping writes are incorrect");
    }

    async fn test_resize_then_open<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        {
            let (blob, _) = storage
                .open("test_resize_then_open", b"test_blob")
                .await
                .unwrap();

            // Write some data
            blob.write_at(0, b"hello world", WriteOptions::default())
                .await
                .unwrap();

            // Resize the blob
            blob.resize(5).await.unwrap();

            // Sync the blob
            blob.sync().await.unwrap();
        }

        // Reopen the blob
        let (blob, len) = storage
            .open("test_resize_then_open", b"test_blob")
            .await
            .unwrap();
        assert_eq!(len, 5, "Blob length after resize is incorrect");

        // Read back the data
        let read = blob
            .read_at(0, 5, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read, b"hello", "Resized data is incorrect");
    }

    /// Test that partition names are validated correctly.
    async fn test_partition_name_validation<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Valid partition names should not return PartitionNameInvalid
        for valid in [
            "partition",
            "my_partition",
            "my-partition",
            "partition123",
            "A1",
        ] {
            assert!(
                !matches!(
                    storage.open(valid, b"blob").await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by open"
            );
            assert!(
                !matches!(
                    storage.remove(valid, None).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by remove"
            );
            assert!(
                !matches!(
                    storage.scan(valid).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Valid partition name '{valid}' should be accepted by scan"
            );
        }

        // Invalid partition names should return PartitionNameInvalid
        for invalid in [
            "my/partition",
            "my.partition",
            "my partition",
            "../escape",
            "",
        ] {
            assert!(
                matches!(
                    storage.open(invalid, b"blob").await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by open"
            );
            assert!(
                matches!(
                    storage.remove(invalid, None).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by remove"
            );
            assert!(
                matches!(
                    storage.scan(invalid).await,
                    Err(crate::Error::PartitionNameInvalid(_))
                ),
                "Invalid partition name '{invalid}' should be rejected by scan"
            );
        }
    }

    /// Test that opening a blob with an incompatible version range returns an error.
    async fn test_blob_version_mismatch<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Create a blob with version 1
        let (blob, _, blob_version) = storage
            .open_versioned(
                "test_version_mismatch",
                b"blob",
                BlobVersion::new(1)..=BlobVersion::new(1),
            )
            .await
            .unwrap();
        assert_eq!(blob_version, BlobVersion::new(1));
        blob.sync().await.unwrap();
        drop(blob);

        // Reopen with a range that includes version 1
        let (_, _, blob_version) = storage
            .open_versioned(
                "test_version_mismatch",
                b"blob",
                BlobVersion::new(0)..=BlobVersion::new(2),
            )
            .await
            .unwrap();
        assert_eq!(blob_version, BlobVersion::new(1));

        // Try to open with version range that excludes version 1
        let result = storage
            .open_versioned(
                "test_version_mismatch",
                b"blob",
                BlobVersion::new(2)..=BlobVersion::new(3),
            )
            .await;
        assert!(
            matches!(
                result,
                Err(crate::Error::BlobVersionMismatch { expected, found })
                if expected == (BlobVersion::new(2)..=BlobVersion::new(3)) && found == BlobVersion::new(1)
            ),
            "Expected BlobVersionMismatch error"
        );
    }

    /// Test aligned-layout blob creation, reopen, and resize through logical offsets.
    async fn test_aligned_layout<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        // Create an aligned blob and write/read through logical offsets.
        let (blob, size, _) = storage
            .open_versioned(
                "test_aligned_layout",
                b"blob",
                BlobVersion::new(0)..=BlobVersion::new(0),
            )
            .await
            .unwrap();
        assert_eq!(size, 0);
        blob.write_at(0, b"hello world".to_vec(), WriteOptions::default())
            .await
            .unwrap();
        blob.sync().await.unwrap();
        let read = blob
            .read_at(0, 11, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read.as_ref(), b"hello world");
        drop(blob);

        // Reopen honors the recorded layout and logical size.
        let (blob, size, _) = storage
            .open_versioned(
                "test_aligned_layout",
                b"blob",
                BlobVersion::new(0)..=BlobVersion::new(0),
            )
            .await
            .unwrap();
        assert_eq!(size, 11);
        let read = blob
            .read_at(6, 5, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read.as_ref(), b"world");

        // Resize preserves logical semantics.
        blob.resize(5).await.unwrap();
        blob.sync().await.unwrap();
        drop(blob);
        let (blob, size, _) = storage
            .open_versioned(
                "test_aligned_layout",
                b"blob",
                BlobVersion::new(0)..=BlobVersion::new(0),
            )
            .await
            .unwrap();
        assert_eq!(size, 5);
        let read = blob
            .read_at(0, 5, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        assert_eq!(read.as_ref(), b"hello");
        drop(blob);
    }

    /// Test that read_at with zero length returns an empty buffer.
    async fn test_read_zero_length<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_zero_len", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello", WriteOptions::default())
            .await
            .unwrap();

        // read_at with len=0 should succeed and return empty
        let output = blob.read_at(0, 0, ReadOptions::default()).await.unwrap();
        assert_eq!(output.len(), 0);

        // read_at_buf with len=0 should also succeed
        let buf = IoBufMut::with_capacity(16);
        let output = blob
            .read_at_buf(0, 0, buf, ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(output.len(), 0);
    }

    /// Test that read_at_buf returns the same buffer that was passed in (contract verification).
    async fn test_read_at_buf_returns_same_buffer<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_contract", b"blob")
            .await
            .unwrap();

        // Write test data
        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        // Test with single buffer - verify same buffer is returned
        let input_buf = IoBufMut::zeroed(11);
        let input_ptr = input_buf.as_ref().as_ptr();
        let output = blob
            .read_at_buf(0, 11, input_buf, ReadOptions::default())
            .await
            .unwrap();
        assert!(
            output.is_single(),
            "Single input should return single output"
        );
        let output_ptr = output.chunk().as_ptr();
        assert_eq!(
            input_ptr, output_ptr,
            "read_at must return the same buffer that was passed in"
        );
        assert_eq!(output.chunk(), b"hello world");

        // Test with multi-chunk buffers - verify same buffers are returned with correct data
        let buf1 = IoBufMut::zeroed(5);
        let buf2 = IoBufMut::zeroed(6);
        let ptr1 = buf1.as_ref().as_ptr();
        let ptr2 = buf2.as_ref().as_ptr();
        let input_bufs = IoBufsMut::from(vec![buf1, buf2]);
        assert!(!input_bufs.is_single(), "Should be multi-chunk");

        let mut output = blob
            .read_at_buf(0, 11, input_bufs, ReadOptions::default())
            .await
            .unwrap();
        assert!(
            !output.is_single(),
            "Multi-chunk input should return multi-chunk output"
        );

        // Verify the buffers are the same and contain correct data.
        assert_eq!(
            output.chunk().as_ptr(),
            ptr1,
            "First chunk must be the same buffer"
        );
        assert_eq!(output.chunk(), b"hello");
        output.advance(5);
        assert_eq!(
            output.chunk().as_ptr(),
            ptr2,
            "Second chunk must be the same buffer"
        );
        assert_eq!(output.chunk(), b" world");
        output.advance(6);
        assert_eq!(output.remaining(), 0);

        // when requested len only fills the first chunk, read_at_buf
        // should still preserve caller-provided multi-chunk layout.
        let buf1 = IoBufMut::zeroed(2);
        let buf2 = IoBufMut::zeroed(2);
        let ptr1 = buf1.as_ref().as_ptr();
        let input_bufs = IoBufsMut::from(vec![buf1, buf2]);
        assert!(!input_bufs.is_single(), "Should be multi-chunk");

        let output = blob
            .read_at_buf(0, 2, input_bufs, ReadOptions::default())
            .await
            .unwrap();
        assert!(
            !output.is_single(),
            "Multi-chunk input should remain multi-chunk when len only uses first chunk"
        );
        assert_eq!(
            output.chunk().as_ptr(),
            ptr1,
            "First chunk must be the same buffer"
        );
        assert_eq!(output.chunk(), b"he");
    }

    /// Test that read_at_buf panics when buffer capacity < len.
    async fn test_read_at_buf_insufficient_capacity<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_buf_capacity", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        // Single buffer with capacity 5, request 11 bytes
        let buf = IoBufMut::with_capacity(5);
        let result =
            std::panic::AssertUnwindSafe(blob.read_at_buf(0, 11, buf, ReadOptions::default()))
                .catch_unwind()
                .await;
        assert!(
            result.is_err(),
            "Expected panic for insufficient single buffer capacity"
        );

        // Chunked buffers with total capacity 8, request 11 bytes
        let bufs = IoBufsMut::from(vec![IoBufMut::with_capacity(4), IoBufMut::with_capacity(4)]);
        let result =
            std::panic::AssertUnwindSafe(blob.read_at_buf(0, 11, bufs, ReadOptions::default()))
                .catch_unwind()
                .await;
        assert!(
            result.is_err(),
            "Expected panic for insufficient multi-chunk buffer capacity"
        );
    }

    /// Test that read_at_buf works when buffer capacity exceeds len.
    async fn test_read_at_buf_larger_capacity<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage
            .open("test_read_at_buf_large_cap", b"blob")
            .await
            .unwrap();

        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        // Buffer with capacity 64, request only 11 bytes
        let buf = IoBufMut::with_capacity(64);
        assert_eq!(buf.len(), 0, "with_capacity should start at len 0");
        let output = blob
            .read_at_buf(0, 11, buf, ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(output.len(), 11);
        assert_eq!(output.coalesce(), b"hello world");

        // Buffer with capacity 64, request only 5 bytes (partial read)
        let buf = IoBufMut::with_capacity(64);
        let output = blob
            .read_at_buf(0, 5, buf, ReadOptions::default())
            .await
            .unwrap();
        assert_eq!(output.len(), 5);
        assert_eq!(output.coalesce(), b"hello");
    }

    /// Test that read options do not change functional read behavior.
    async fn test_read_options<S>(storage: &S)
    where
        S: Storage + Send + Sync,
        S::Blob: Send + Sync,
    {
        let (blob, _) = storage.open("test_read_options", b"blob").await.unwrap();
        blob.write_at(0, b"hello world", WriteOptions::default())
            .await
            .unwrap();

        // Exact reads must return the same bytes under either cache policy.
        let default = blob
            .read_at(0, 11, ReadOptions::default())
            .await
            .unwrap()
            .coalesce();
        let uncached = blob
            .read_at(0, 11, ReadOptions::DONT_CACHE)
            .await
            .unwrap()
            .coalesce();
        assert_eq!(default.as_ref(), uncached.as_ref());

        // Zero-length and past-EOF behavior is policy-independent.
        let default = blob.read_at(0, 0, ReadOptions::default()).await.unwrap();
        let uncached = blob.read_at(0, 0, ReadOptions::DONT_CACHE).await.unwrap();
        assert_eq!(default.len(), 0);
        assert_eq!(uncached.len(), 0);

        assert!(blob.read_at(0, 12, ReadOptions::default()).await.is_err());
        assert!(blob.read_at(0, 12, ReadOptions::DONT_CACHE).await.is_err());

        // Vectored destinations preserve their shape and content under either policy.
        for options in [ReadOptions::default(), ReadOptions::DONT_CACHE] {
            let bufs =
                IoBufsMut::from(vec![IoBufMut::with_capacity(5), IoBufMut::with_capacity(6)]);
            let output = blob.read_at_buf(0, 11, bufs, options).await.unwrap();
            assert!(!output.is_single());
            assert_eq!(output.coalesce(), b"hello world");
        }
    }
}
