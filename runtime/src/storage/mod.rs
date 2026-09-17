//! Implementations of the `Storage` trait that can be used by the runtime.

use commonware_macros::stability_scope;

stability_scope!(BETA, cfg(not(target_arch = "wasm32")) {
    use crate::{BlobVersion, Error};
    use ::tokio::sync::watch;
    use cfg_if::cfg_if;
    use commonware_formatting::hex;
    use commonware_utils::sync::Mutex;
    #[cfg(not(target_os = "linux"))]
    use std::collections::HashSet;
    use std::{
        collections::HashMap,
        fs::File,
        io::{self, Read as _, Seek as _, SeekFrom},
        ops::RangeInclusive,
        path::Path,
        ptr,
        sync::{
            Arc, Weak,
            atomic::{AtomicU64, Ordering},
        },
    };
    #[cfg(target_os = "linux")]
    use std::os::fd::AsRawFd;

    cfg_if! {
        if #[cfg(test)] {
            use ::tokio::sync::oneshot::Sender as OneshotSender;
            use std::sync::mpsc::{Receiver as MpscReceiver, Sender as MpscSender};
        }
    }

    cfg_if! {
        if #[cfg(target_os = "linux")] {
            /// Make what a prior process wrote crash-durable before any storage structure reads by
            /// flushing the whole filesystem containing `dir` with `syncfs(2)`.
            ///
            /// Assumes storage lives on a single filesystem. Reliable error detection needs kernel
            /// >= 5.8.
            pub(crate) fn sync(dir: &Path) -> io::Result<()> {
                let file = File::open(dir)?;
                // SAFETY: `file` owns a valid fd that lives across the call; `syncfs` takes only
                // that fd, performs no memory access, and returns -1 on error.
                if unsafe { libc::syncfs(file.as_raw_fd()) } == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }
        } else {
            /// Make what a prior process wrote crash-durable before any storage structure reads.
            ///
            /// No filesystem-wide flush with that guarantee exists here, so this does nothing and
            /// the first open of each existing blob flushes it instead (see [Pending::first_open]).
            pub(crate) const fn sync(_: &Path) -> io::Result<()> {
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

    /// The live open of each blob name and the durability debt its dropped handles left behind.
    ///
    /// A name has at most one live open. Its identity binds settlement to that open, and the
    /// entry retains outstanding work, unflushed state and failures until the name is removed or
    /// recreated. Dropping a handle performs no I/O: the next open of the name establishes
    /// whatever durability the dropped handles left behind, and a failure to do so is retained
    /// for every later open until the blob is removed.
    #[derive(Default)]
    pub(crate) struct Pending {
        entries: Mutex<HashMap<(String, Vec<u8>), Entry>>,
        /// Names this instance has created or flushed. Nothing flushes the filesystem at startup
        /// here, so the first open of any other existing name owes a flush before trusting the
        /// file. Removing a name drops it: a later open of that name creates the blob and owes
        /// nothing.
        #[cfg(not(target_os = "linux"))]
        flushed: Mutex<HashSet<(String, Vec<u8>)>>,
        #[cfg(test)]
        test: TestState,
    }

    /// Counters and hooks for controlling storage lifecycle tests.
    ///
    /// Each optional hook is consumed by the next matching operation. Paired channels announce
    /// arrival, then wait for a release message or for the release sender to be dropped.
    #[cfg(test)]
    #[derive(Default)]
    struct TestState {
        /// Number of flushes an open performed to establish a settled predecessor's debt.
        completions: AtomicU64,
        /// Report that the next completion is about to flush the file, then pause it.
        before_complete: Mutex<Option<(OneshotSender<()>, MpscReceiver<()>)>>,
        /// Fail the next flush through a blob handle or an open's completion with this error.
        fail_flush: Mutex<Option<Error>>,
        /// Pause namespace dispatch after sending or dropping its result and releasing its lock
        /// and directory hold, before returning to the caller.
        after_dispatch: Mutex<Option<(OneshotSender<()>, MpscReceiver<()>)>>,
        /// Fail header creation with `Error::Closed` after writing this many bytes, capped at the
        /// header length.
        fail_creation_after: Mutex<Option<usize>>,
        /// Report the current generation strong count after a liveness check, then pause while
        /// the registry remains locked.
        after_identity_observation: Mutex<Option<(MpscSender<usize>, MpscReceiver<()>)>>,
        /// Pause an open after its predecessor settled, before it reads the debt and the file's
        /// length.
        before_metadata: Mutex<Option<(OneshotSender<()>, MpscReceiver<()>)>>,
        /// Pause the next attachment before it locks the registry, letting predecessor work retire.
        before_attach: Mutex<Option<(OneshotSender<()>, MpscReceiver<()>)>>,
    }

    #[derive(Default)]
    struct Entry {
        /// Liveness checks must not acquire an owner: its destructor locks this registry.
        identity: Weak<Generation>,
        /// Fires once every operation issued through the previous open has finished.
        settle: Option<Receiver>,
        /// Debt the previous opens left, released by the open that establishes it.
        dirty: bool,
        /// A durability failure retained until the name is removed or recreated.
        failed: Option<Error>,
    }

    impl Entry {
        /// Whether the entry carries nothing a later open must observe.
        const fn is_clear(&self) -> bool {
            self.settle.is_none() && !self.dirty && self.failed.is_none()
        }
    }

    /// The live open of one namespace entry, dropped with the last handle of that open.
    pub(crate) struct Generation {
        pending: Arc<Pending>,
        key: (String, Vec<u8>),
    }

    impl Generation {
        /// Release the name for a later open, returning the sender that settles this open once
        /// every operation issued through it has finished. `None` once the name was removed or
        /// recreated, or while an earlier open is still settling.
        pub(crate) fn release(&self) -> Option<Sender> {
            self.pending.start(self)
        }
    }

    impl Drop for Generation {
        fn drop(&mut self) {
            let mut entries = self.pending.entries.lock();
            if entries.get(&self.key).is_some_and(|entry| {
                ptr::eq(entry.identity.as_ptr(), self) && entry.is_clear()
            }) {
                entries.remove(&self.key);
            }
        }
    }

    /// Whether the previous open of a name has settled.
    type Receiver = watch::Receiver<bool>;
    pub(crate) type Sender = watch::Sender<bool>;

    impl Pending {
        /// Attach a fresh open to a name while the backend holds its namespace lock.
        ///
        /// Returns [Error::BlobAlreadyOpen] while a handle from an earlier open is alive. Returns
        /// the name's retained failure until the name is removed. Otherwise returns the open's generation,
        /// the receiver that fires once a still-settling predecessor has finished its operations,
        /// and whether the name carries debt or outstanding work the open must observe through
        /// [Self::debt] before trusting the file. Descriptor metadata must be observed after
        /// attachment, or after awaiting the returned receiver.
        pub(crate) fn attach(
            self: &Arc<Self>,
            partition: &str,
            name: &[u8],
        ) -> Result<(Arc<Generation>, Option<Receiver>, bool), Error> {
            #[cfg(test)]
            if let Some((entered, released)) = self.test.before_attach.lock().take() {
                let _ = entered.send(());
                let _ = released.recv();
            }
            let key = (partition.to_owned(), name.to_vec());
            let mut entries = self.entries.lock();
            let entry = entries.entry(key.clone()).or_default();
            let live = entry.identity.strong_count() != 0;
            #[cfg(test)]
            self.observe_identity(&entry.identity);
            if live {
                return Err(Error::BlobAlreadyOpen(partition.to_owned(), hex(name)));
            }
            if let Some(failed) = &entry.failed {
                return Err(failed.clone());
            }
            let generation = Arc::new(Generation { pending: self.clone(), key });
            entry.identity = Arc::downgrade(&generation);
            let owed = entry.settle.is_some() || entry.dirty;
            Ok((generation, entry.settle.clone(), owed))
        }

        /// Register settlement only while this identity still owns its name and no earlier
        /// open is still settling.
        fn start(&self, generation: &Generation) -> Option<Sender> {
            let mut entries = self.entries.lock();
            let entry = entries.get_mut(&generation.key)?;
            if !ptr::eq(entry.identity.as_ptr(), generation) || entry.settle.is_some() {
                return None;
            }
            let (sender, receiver) = watch::channel(false);
            entry.settle = Some(receiver);
            Some(sender)
        }

        /// Settle a dropped open once every operation issued through it has finished: record the
        /// debt and any failure it leaves behind, then wake the open waiting for it.
        ///
        /// Debt only accumulates. The open that establishes it releases it through [Self::clear].
        pub(crate) fn settle(
            &self,
            key: &(String, Vec<u8>),
            sender: Sender,
            dirty: bool,
            failure: Option<Error>,
        ) {
            {
                let mut entries = self.entries.lock();
                if let Some(entry) = entries.get_mut(key)
                    && entry.settle.as_ref().is_some_and(|receiver| receiver.same_channel(&sender.subscribe()))
                {
                    entry.settle = None;
                    entry.dirty |= dirty;
                    if failure.is_some() {
                        entry.failed = failure;
                    }
                    let live = entry.identity.strong_count() != 0;
                    #[cfg(test)]
                    self.observe_identity(&entry.identity);
                    if !live && entry.is_clear() {
                        entries.remove(key);
                    }
                }
            }
            let _ = sender.send(true);
        }

        /// Wait for the previous open's operations to finish.
        pub(crate) async fn wait(receiver: Option<Receiver>) -> Result<(), Error> {
            let Some(mut receiver) = receiver else {
                return Ok(());
            };
            receiver
                .wait_for(|settled| *settled)
                .await
                .map(|_| ())
                .map_err(|_| Error::Closed)
        }

        /// The debt the open identified by `identity` must establish before trusting its file,
        /// or the failure retained for its name. Read after the predecessor settled. Nothing is
        /// owed once the name was removed or recreated under this open.
        ///
        /// The identity is weak so a cancelled open's completion neither keeps the name open nor
        /// publishes into a successor's entry.
        pub(crate) fn debt(&self, key: &(String, Vec<u8>), identity: &Weak<Generation>) -> Result<bool, Error> {
            let entries = self.entries.lock();
            let Some(entry) = entries.get(key) else {
                return Ok(false);
            };
            if !Weak::ptr_eq(&entry.identity, identity) {
                return Ok(false);
            }
            if let Some(failed) = &entry.failed {
                return Err(failed.clone());
            }
            Ok(entry.dirty)
        }

        /// Publish the outcome of establishing the debt read through [Self::debt]: success
        /// releases it and a failure is retained for every later open until the name is removed.
        /// Ignored once the name was removed or recreated under this open.
        pub(crate) fn clear(
            &self,
            key: &(String, Vec<u8>),
            identity: &Weak<Generation>,
            result: &Result<(), Error>,
        ) {
            let mut entries = self.entries.lock();
            let Some(entry) = entries.get_mut(key) else {
                return;
            };
            if !Weak::ptr_eq(&entry.identity, identity) {
                return;
            }
            match result {
                Ok(()) => entry.dirty = false,
                Err(error) => entry.failed = Some(error.clone()),
            }
        }

        cfg_if! {
            if #[cfg(target_os = "linux")] {
                /// Whether the first open of `generation`'s name through this instance owes a
                /// flush. Linux flushes the filesystem at startup, so no open does.
                pub(crate) const fn first_open(&self, _: &Generation, _: bool) -> bool {
                    false
                }
            } else {
                /// Whether the first open of `generation`'s name through this instance owes a
                /// flush. Nothing flushes the filesystem at startup here, so an existing blob owes
                /// one the first time this instance opens it. Creations are durable on return and
                /// owe nothing.
                pub(crate) fn first_open(&self, generation: &Generation, existing: bool) -> bool {
                    let first = self.flushed.lock().insert(generation.key.clone());
                    if !(first && existing) {
                        return false;
                    }
                    let mut entries = self.entries.lock();
                    if let Some(entry) = entries.get_mut(&generation.key)
                        && ptr::eq(entry.identity.as_ptr(), generation)
                    {
                        entry.dirty = true;
                    }
                    true
                }
            }
        }

        /// Retain a creation failure for `generation`'s name until it is removed or recreated.
        pub(crate) fn fail(&self, generation: &Generation, error: Error) {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.get_mut(&generation.key)
                && ptr::eq(entry.identity.as_ptr(), generation)
            {
                entry.failed = Some(error);
            }
        }

        /// Detach a removed name, or every name in a removed partition.
        pub(crate) fn forget(&self, partition: &str, name: Option<&[u8]>) {
            if let Some(name) = name {
                let key = (partition.to_owned(), name.to_vec());
                self.entries.lock().remove(&key);
                #[cfg(not(target_os = "linux"))]
                self.flushed.lock().remove(&key);
            } else {
                self.entries.lock().retain(|(stored, _), _| {
                    stored != partition
                });
                #[cfg(not(target_os = "linux"))]
                self.flushed.lock().retain(|(stored, _)| stored != partition);
            }
        }
    }

    #[cfg(test)]
    impl Pending {
        /// Report the next observed generation's strong count, then wait for release.
        fn observe_identity(&self, identity: &Weak<Generation>) {
            let hook = self.test.after_identity_observation.lock().take();
            if let Some((entered, release)) = hook {
                entered.send(identity.strong_count()).unwrap();
                let _ = release.recv();
            }
        }

        /// Take the injected failure for the next flush, if any.
        pub(crate) fn take_flush_failure(&self) -> Option<Error> {
            self.test.fail_flush.lock().take()
        }

        /// Report that a completion is about to flush, then wait for release.
        pub(crate) fn before_complete(&self) {
            let hook = self.test.before_complete.lock().take();
            if let Some((entered, released)) = hook {
                let _ = entered.send(());
                let _ = released.recv();
            }
        }

        /// Count a completion that established a predecessor's debt.
        pub(crate) fn completed(&self) {
            self.test.completions.fetch_add(1, Ordering::AcqRel);
        }

        /// Number of names whose previous open has not settled yet.
        pub(crate) fn outstanding(&self) -> usize {
            self.entries.lock().values().filter(|entry| entry.settle.is_some()).count()
        }

        /// Whether `name` carries debt or a retained failure no open has established yet.
        pub(crate) fn owes(&self, partition: &str, name: &[u8]) -> bool {
            self.entries
                .lock()
                .get(&(partition.to_owned(), name.to_vec()))
                .is_some_and(|entry| entry.dirty || entry.failed.is_some())
        }

        /// Number of completions opens performed for settled predecessors.
        pub(crate) fn completions(&self) -> u64 {
            self.test.completions.load(Ordering::Acquire)
        }
    }

    /// Tracks the writes to one blob file that no completed sync covers.
    ///
    /// Shared by every handle of one open, it counts mutations requiring a full-file barrier.
    /// Each sync credits only mutations completed before it began, so a mutation racing a sync
    /// stays dirty. It retains the first durability failure so a later flush cannot certify
    /// bytes the kernel already reported lost.
    #[derive(Default)]
    pub(crate) struct Tracker {
        written: AtomicU64,
        completed: AtomicU64,
        synced: AtomicU64,
        failed: Mutex<Option<Error>>,
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

        /// Credit a completed sync unless a durability failure was already retained.
        pub(crate) fn end_sync(&self, seen: u64) -> Result<(), Error> {
            let failed = self.failed.lock();
            if let Some(error) = failed.as_ref() {
                return Err(error.clone());
            }
            self.synced.fetch_max(seen, Ordering::AcqRel);
            Ok(())
        }

        /// Whether writes were issued that no completed sync covers.
        pub(crate) fn is_dirty(&self) -> bool {
            self.written.load(Ordering::Acquire) != self.synced.load(Ordering::Acquire)
        }

        /// Retain the first durability failure this open observed.
        pub(crate) fn poison(&self, error: &Error) {
            let mut failed = self.failed.lock();
            if failed.is_none() {
                *failed = Some(error.clone());
            }
        }

        /// The retained durability failure, if any.
        pub(crate) fn failure(&self) -> Option<Error> {
            self.failed.lock().clone()
        }
    }

    #[cfg(test)]
    impl Tracker {
        /// Record a sync that found nothing to persist.
        ///
        /// Callers sync freely and the runtime skips the device flush when every completed
        /// mutation through the open is covered.
        pub(crate) fn skip_sync(&self) {
            self.skipped.fetch_add(1, Ordering::AcqRel);
        }

        /// Number of syncs skipped because the open was clean.
        pub(crate) fn skipped(&self) -> u64 {
            self.skipped.load(Ordering::Acquire)
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
        let requested = Header::resolve_len(raw_len);
        let mut raw = Vec::with_capacity(requested);
        file.seek(SeekFrom::Start(0))
            .map_err(|_| Error::ReadFailed)?;
        file.take(requested as u64).read_to_end(&mut raw).map_err(|_| Error::ReadFailed)?;

        // V0's prefix includes mutable payload that may shrink after metadata was read.
        // A complete prefix must retain the original length, which yields the logical size.
        let parse_len = if raw.len() < requested { raw.len() as u64 } else { raw_len };
        header::resolve(&raw, parse_len, layouts, versions, partition, name)
    }

    pub(crate) mod hold;
});

stability_scope!(ALPHA {
    pub mod audited;
    pub mod faulty;
    pub mod memory;
    pub mod open;
});
stability_scope!(ALPHA, cfg(all(target_os = "linux", feature = "iouring")) {
    pub mod iouring;
});
stability_scope!(BETA, cfg(not(target_arch = "wasm32")) {
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
        Blob, BlobVersion, Buf, IoBuf, IoBufMut, IoBufs, IoBufsMut, ReadOptions, Spawner, Storage,
        WriteOptions,
    };
    use futures::FutureExt;

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) mod shared {
        use super::super::Pending;
        use crate::{Blob as _, BufferPool, Error, ReadOptions, WriteOptions, buffer::Write};
        use ::tokio::time::timeout;
        use commonware_utils::NZUsize;
        use std::{sync::mpsc, time::Duration};

        /// An untouched creation leaves no debt for a later open.
        pub(crate) async fn check_untouched_creation_leaves_no_debt<S: crate::Storage>(
            storage: &S,
            pending: &Pending,
        ) {
            let before = pending.completions();
            let (blob, _) = storage.open("durable_creation", b"blob").await.unwrap();
            drop(blob);
            let owed = pending.owes("durable_creation", b"blob");

            let (blob, size) = storage.open("durable_creation", b"blob").await.unwrap();
            drop(blob);
            let completions = pending.completions() - before;
            storage.remove("durable_creation", None).await.unwrap();

            assert!(!owed, "successful creation must leave no durability debt");
            assert_eq!(size, 0);
            assert_eq!(completions, 0, "untouched creation needs no reopen flush");
        }

        /// Failed creation must not expose an unflushed header as a valid blob.
        ///
        /// An incomplete header is recreated on the next open. A complete header retains the
        /// creation failure across repeated opens until the name is removed. Failed creation
        /// leaves no payload mutations for a later open to flush.
        pub(crate) async fn check_failed_creation<S: crate::Storage>(
            storage: &S,
            pending: &Pending,
        ) {
            let completions = pending.completions();

            // Stop after writing either a partial or complete header.
            for partial in [true, false] {
                *pending.test.fail_creation_after.lock() =
                    Some(if partial { 1 } else { usize::MAX });
                assert!(matches!(
                    storage.open("failed_creation", b"blob").await,
                    Err(Error::Closed)
                ));

                // Repeated opens must preserve the failure even though the header is parseable.
                if !partial {
                    for _ in 0..2 {
                        assert!(
                            matches!(
                                storage.open("failed_creation", b"blob").await,
                                Err(Error::Closed)
                            ),
                            "a parseable header must not hide the failed creation barrier"
                        );
                    }
                    storage
                        .remove("failed_creation", Some(b"blob"))
                        .await
                        .unwrap();
                }

                // Both a torn header and an absent name must yield a fresh, empty blob.
                let (blob, size) = storage.open("failed_creation", b"blob").await.unwrap();
                assert_eq!(size, 0);
                drop(blob);
                storage.remove("failed_creation", None).await.unwrap();
            }
            assert_eq!(
                pending.completions(),
                completions,
                "failed creation must not leave debt"
            );
        }

        /// Unlinking a dirty blob keeps its handles readable and leaves nothing to flush.
        ///
        /// Covers name and partition removal with the last handle dropped before or after the
        /// unlink. Removal forgets the name's debt, so a later open creates a fresh blob
        /// without flushing a file that no longer exists.
        pub(crate) async fn check_remove_live_dirty_owner<S: crate::Storage>(
            storage: &S,
            pending: &Pending,
            pool: &BufferPool,
        ) {
            for by_name in [true, false] {
                for unlink_first in [false, true] {
                    // The write exceeds the buffer capacity and reaches the blob without a
                    // sync, leaving dirty data behind the final handle.
                    let partition = "remove_live_dirty";
                    let name = b"blob";
                    let (blob, size) = storage.open(partition, name).await.unwrap();
                    let mut writer = Write::new(blob, size, NZUsize!(1), pool.clone());
                    writer.write_at(0, b"dirty").await.unwrap();
                    writer.wait_for_sync().await.unwrap();
                    let completions = pending.completions();
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
                    assert!(
                        !pending.owes(partition, name),
                        "removal must forget the name's debt"
                    );

                    // The name is fresh again and nothing is flushed on its behalf.
                    let (blob, size) = storage.open(partition, name).await.unwrap();
                    assert_eq!(size, 0);
                    drop(blob);
                    assert_eq!(pending.completions(), completions);
                    storage.remove(partition, None).await.unwrap();
                }
            }
        }

        /// A write whose future was dropped lands before the next open reports the blob's
        /// length or exposes its bytes.
        ///
        /// Reopening must wait for any remaining write and sync work after the last handle
        /// drops, even though the caller no longer observes the write's result.
        pub(crate) async fn check_orphaned_write<S: crate::Storage>(storage: &S) {
            // Poll once to submit the I/O before abandoning its future and final handle.
            let (blob, _) = storage.open("orphaned_write", b"blob").await.unwrap();
            let mut write = Box::pin(blob.write_at(0, b"orphaned", WriteOptions::default()));
            let _ = futures::poll!(write.as_mut());
            drop(write);
            drop(blob);

            let (blob, len) = storage.open("orphaned_write", b"blob").await.unwrap();
            assert_eq!(len, 8);
            let read = blob.read_at(0, 8, ReadOptions::default()).await.unwrap();
            assert_eq!(read.coalesce().as_ref(), b"orphaned");
            drop(blob);
            storage.remove("orphaned_write", None).await.unwrap();
        }

        /// Successful `SYNC` writes leave nothing for a reopen to flush.
        ///
        /// Mixing plain and durable writes must retain any debt the backend's write barrier
        /// did not cover, regardless of the order of those writes.
        pub(crate) async fn check_sync_writes<S: crate::Storage>(storage: &S, pending: &Pending) {
            // The cache hint must not change durability or require a flush on reopen.
            for (case, options) in [
                WriteOptions::SYNC,
                WriteOptions::SYNC | WriteOptions::DONT_CACHE,
            ]
            .into_iter()
            .enumerate()
            {
                let before = pending.completions();
                let (blob, _) = storage.open("durable_writes", &[case as u8]).await.unwrap();
                blob.write_at(0, b"first", options).await.unwrap();
                blob.write_at(5, b"second", options).await.unwrap();
                drop(blob);
                let (blob, size) = storage.open("durable_writes", &[case as u8]).await.unwrap();
                assert_eq!(size, 11);
                assert_eq!(
                    blob.read_at(0, 11, ReadOptions::default())
                        .await
                        .unwrap()
                        .coalesce()
                        .as_ref(),
                    b"firstsecond"
                );
                drop(blob);
                assert_eq!(
                    pending.completions(),
                    before,
                    "successful durable writes need no reopen flush"
                );
            }

            // A durable write cannot hide an uncovered plain write in either order.
            for plain_first in [false, true] {
                let before = pending.completions();
                let name = [2, u8::from(plain_first)];
                let (blob, _) = storage.open("durable_writes", &name).await.unwrap();
                let (first, second) = if plain_first {
                    (WriteOptions::default(), WriteOptions::SYNC)
                } else {
                    (WriteOptions::SYNC, WriteOptions::default())
                };
                blob.write_at(0, b"first", first).await.unwrap();
                blob.write_at(5, b"second", second).await.unwrap();
                drop(blob);
                let (blob, size) = storage.open("durable_writes", &name).await.unwrap();
                assert_eq!(size, 11);
                assert_eq!(
                    blob.read_at(0, 11, ReadOptions::default())
                        .await
                        .unwrap()
                        .coalesce()
                        .as_ref(),
                    b"firstsecond"
                );
                drop(blob);

                // Linux's per-write sync covers only the durable write's range. Other
                // platforms use a full-file sync, which also covers an earlier plain write.
                let needs_flush = !plain_first || cfg!(target_os = "linux");
                assert_eq!(
                    pending.completions() - before,
                    u64::from(needs_flush),
                    "plain_first={plain_first}"
                );
            }
        }

        /// Reopening a replacement flushes its debt while another partition remains usable.
        ///
        /// Covers name and partition removal while the old handle remains readable. Dropping
        /// that handle must not record debt for the replacement, and the replacement's reopen
        /// must not return before its own flush completes.
        pub(crate) async fn check_recreate_reopen<S: crate::Storage>(
            storage: &S,
            pending: &Pending,
        ) {
            // Make the independent blob durable so its later open owes nothing.
            let (ready, _) = storage.open("independent", b"ready").await.unwrap();
            ready.sync().await.unwrap();
            drop(ready);
            for remove_name in [true, false] {
                let partition = "recreate_pending";
                let name = b"blob";
                let (old, _) = storage.open(partition, name).await.unwrap();
                old.write_at(0, b"old", WriteOptions::default())
                    .await
                    .unwrap();
                storage
                    .remove(partition, remove_name.then_some(name.as_slice()))
                    .await
                    .unwrap();
                assert_eq!(
                    old.read_at(0, 3, ReadOptions::default())
                        .await
                        .unwrap()
                        .coalesce()
                        .as_ref(),
                    b"old"
                );

                let (current, len) = storage.open(partition, name).await.unwrap();
                assert_eq!(len, 0);
                let reader = current.clone();
                current
                    .write_at(0, b"new", WriteOptions::default())
                    .await
                    .unwrap();

                // Block the reopen's flush. The replacement stays alive through a clone while
                // the removed open drops, so only the replacement may record debt. Dropping
                // the sender also releases the worker if an assertion unwinds.
                let (entered, _entering) = ::tokio::sync::oneshot::channel();
                let (release, gate) = mpsc::channel();
                *pending.test.before_complete.lock() = Some((entered, gate));
                let completions = pending.completions();
                drop(current);
                drop(old);
                drop(reader);

                let mut reopen = Box::pin(storage.open(partition, name));
                let early = timeout(Duration::from_millis(50), &mut reopen).await;
                let completed_early = early.is_ok();

                // Waiting for this flush must leave the namespace lock available to unrelated
                // scans and opens.
                let clean_progress = timeout(Duration::from_secs(5), async {
                    let names = storage.scan("independent").await?;
                    let (blob, len) = storage.open("independent", b"ready").await?;
                    drop(blob);
                    Ok::<_, Error>((names, len))
                })
                .await;

                // Release the worker before checking outcomes so failures cannot leave it
                // blocked on the gate.
                drop(release);
                let (reopened, len) = match early {
                    Ok(result) => result,
                    Err(_) => reopen.await,
                }
                .unwrap();
                let bytes = reopened
                    .read_at(0, 3, ReadOptions::default())
                    .await
                    .unwrap()
                    .coalesce();
                drop(reopened);
                storage.remove(partition, None).await.unwrap();
                assert_eq!(len, 3);
                assert_eq!(bytes.as_ref(), b"new");
                assert!(
                    !completed_early,
                    "reopen exposed the replacement before its flush"
                );
                assert_eq!(
                    pending.completions() - completions,
                    1,
                    "the replacement's debt is flushed once"
                );
                let (names, len) = clean_progress
                    .expect("a flush blocked another partition")
                    .unwrap();
                assert_eq!(names, vec![b"ready".to_vec()]);
                assert_eq!(len, 0);
            }
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod tracker {
        use crate::{
            Error,
            storage::{Pending, Tracker},
        };
        use std::{
            sync::{Arc, mpsc},
            thread,
            time::{Duration, Instant},
        };

        #[test]
        fn test_synced_writes_are_clean() {
            let tracker = Tracker::default();
            assert!(!tracker.is_dirty());
            tracker.write();
            assert!(tracker.is_dirty());
            tracker.complete();
            let seen = tracker.begin_sync();
            tracker.end_sync(seen).unwrap();
            assert!(!tracker.is_dirty());
        }

        #[test]
        fn test_unlanded_write_is_not_credited() {
            let tracker = Tracker::default();
            tracker.write();

            // The sync began before the write reached the file, so it cannot cover it.
            let seen = tracker.begin_sync();
            tracker.complete();
            tracker.end_sync(seen).unwrap();
            assert!(tracker.is_dirty());
            let later = tracker.begin_sync();
            tracker.end_sync(later).unwrap();
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
            tracker.end_sync(seen).unwrap();
            assert!(tracker.is_dirty());

            // A sync observing both writes clears the state, and a stale completion
            // cannot regress it.
            let later = tracker.begin_sync();
            tracker.end_sync(later).unwrap();
            tracker.end_sync(seen).unwrap();
            assert!(!tracker.is_dirty());
        }

        #[test]
        fn test_first_failure_is_retained() {
            let tracker = Tracker::default();
            assert!(tracker.failure().is_none());
            tracker.poison(&Error::Closed);
            tracker.poison(&Error::ReadFailed);
            assert!(matches!(tracker.failure(), Some(Error::Closed)));
        }

        fn key() -> (String, Vec<u8>) {
            ("a".to_owned(), b"1".to_vec())
        }

        fn check_last_generation_drop_during_observation(settle: bool) {
            let pending = Arc::new(Pending::default());
            let (generation, _, _) = pending.attach("a", b"1").unwrap();
            let identity = Arc::downgrade(&generation);
            let sender = settle.then(|| generation.release().unwrap());
            let outcome = sender.as_ref().map(|sender| sender.subscribe());
            let (entered, entering) = mpsc::channel();
            let (release, released) = mpsc::channel();
            *pending.test.after_identity_observation.lock() = Some((entered, released));
            let (done, finished) = mpsc::channel();
            let observer = {
                let pending = pending.clone();
                let done = done.clone();
                thread::spawn(move || {
                    if let Some(sender) = sender {
                        pending.settle(&key(), sender, false, None);
                    } else {
                        assert!(matches!(
                            pending.attach("a", b"1"),
                            Err(Error::BlobAlreadyOpen(partition, name))
                                if partition == "a" && name == "31"
                        ));
                    }
                    done.send(()).unwrap();
                })
            };
            let timeout = Duration::from_secs(5);
            let owners = entering.recv_timeout(timeout).unwrap();
            let dropper = {
                let done = done.clone();
                thread::spawn(move || {
                    drop(generation);
                    done.send(()).unwrap();
                })
            };

            // Release the external owner while the registry is locked. The strong count detects
            // the last drop. Operation completion and an independent attachment verify progress.
            let deadline = Instant::now() + timeout;
            while identity.strong_count() == owners {
                assert!(Instant::now() < deadline, "generation owner did not drop");
                thread::yield_now();
            }
            release.send(()).unwrap();
            let independent = {
                let pending = pending.clone();
                thread::spawn(move || {
                    drop(pending.attach("independent", b"2").unwrap());
                    done.send(()).unwrap();
                })
            };
            for _ in 0..3 {
                finished
                    .recv_timeout(timeout)
                    .expect("registry deadlocked during generation drop");
            }
            observer.join().unwrap();
            dropper.join().unwrap();
            independent.join().unwrap();
            if let Some(outcome) = outcome {
                assert!(*outcome.borrow());
            }
            assert!(pending.entries.lock().is_empty());
        }

        #[test]
        fn test_last_generation_drop_during_settle() {
            check_last_generation_drop_during_observation(true);
        }

        #[test]
        fn test_last_generation_drop_during_attach() {
            check_last_generation_drop_during_observation(false);
        }

        #[tokio::test]
        async fn test_wait_observes_settling_predecessor() {
            let pending = Arc::new(Pending::default());
            let (generation, wait, owed) = pending.attach("a", b"1").unwrap();
            assert!(!owed);
            Pending::wait(wait).await.unwrap();
            let sender = generation.release().unwrap();
            drop(generation);
            let (generation, wait, owed) = pending.attach("a", b"1").unwrap();
            assert!(owed);
            let waiter = tokio::spawn(Pending::wait(wait));
            tokio::task::yield_now().await;
            assert!(!waiter.is_finished());
            pending.settle(&key(), sender, false, None);
            waiter.await.unwrap().unwrap();
            assert_eq!(pending.outstanding(), 0);
            assert!(!pending.debt(&key(), &Arc::downgrade(&generation)).unwrap());
            drop(generation);
            assert!(pending.entries.lock().is_empty());
        }

        #[test]
        fn test_debt_is_established_by_the_next_open() {
            let pending = Arc::new(Pending::default());
            let (first, _, _) = pending.attach("a", b"1").unwrap();
            let sender = first.release().unwrap();
            drop(first);
            pending.settle(&key(), sender, true, None);
            assert!(pending.owes("a", b"1"));

            // Debt accumulates across settled opens until an open establishes it.
            let (second, wait, owed) = pending.attach("a", b"1").unwrap();
            assert!(wait.is_none());
            assert!(owed);
            assert!(pending.debt(&key(), &Arc::downgrade(&second)).unwrap());
            let sender = second.release().unwrap();
            drop(second);
            pending.settle(&key(), sender, false, None);
            let (third, _, owed) = pending.attach("a", b"1").unwrap();
            assert!(owed);
            assert!(pending.debt(&key(), &Arc::downgrade(&third)).unwrap());
            pending.clear(&key(), &Arc::downgrade(&third), &Ok(()));
            assert!(!pending.debt(&key(), &Arc::downgrade(&third)).unwrap());
            assert!(!pending.owes("a", b"1"));
            drop(third);
            assert!(pending.entries.lock().is_empty());
        }

        #[test]
        fn test_failures_stay_until_forgotten() {
            let pending = Arc::new(Pending::default());

            // A failure published at settlement blocks later opens.
            let (generation, _, _) = pending.attach("a", b"1").unwrap();
            let sender = generation.release().unwrap();
            pending.settle(&key(), sender, false, Some(Error::Closed));
            drop(generation);
            for _ in 0..2 {
                assert!(matches!(pending.attach("a", b"1"), Err(Error::Closed)));
            }
            pending.forget("a", Some(b"1"));

            // A failed completion is retained the same way, and success never overwrites it.
            let (generation, _, _) = pending.attach("a", b"1").unwrap();
            pending.clear(
                &key(),
                &Arc::downgrade(&generation),
                &Err(Error::ReadFailed),
            );
            assert!(matches!(
                pending.debt(&key(), &Arc::downgrade(&generation)),
                Err(Error::ReadFailed)
            ));
            pending.clear(&key(), &Arc::downgrade(&generation), &Ok(()));
            assert!(matches!(
                pending.debt(&key(), &Arc::downgrade(&generation)),
                Err(Error::ReadFailed)
            ));
            drop(generation);
            assert!(matches!(pending.attach("a", b"1"), Err(Error::ReadFailed)));

            // A creation failure is retained until the name is forgotten.
            pending.forget("a", Some(b"1"));
            let (generation, _, _) = pending.attach("a", b"1").unwrap();
            pending.fail(&generation, Error::WriteFailed);
            drop(generation);
            assert!(matches!(pending.attach("a", b"1"), Err(Error::WriteFailed)));
            pending.forget("a", Some(b"1"));
            drop(pending.attach("a", b"1").unwrap());
            assert!(pending.entries.lock().is_empty());
        }

        #[test]
        fn test_stale_settlement_leaves_a_recreated_name_alone() {
            let pending = Arc::new(Pending::default());
            let (old, _, _) = pending.attach("a", b"1").unwrap();
            let stale = old.release().unwrap();
            pending.forget("a", Some(b"1"));
            let (current, _, owed) = pending.attach("a", b"1").unwrap();
            assert!(!owed);

            // The removed open's settlement and outcome must not touch the replacement's entry.
            pending.settle(&key(), stale, true, Some(Error::Closed));
            assert!(old.release().is_none());
            pending.clear(&key(), &Arc::downgrade(&old), &Err(Error::Closed));
            assert!(!pending.owes("a", b"1"));
            assert!(!pending.debt(&key(), &Arc::downgrade(&current)).unwrap());
            drop(old);
            let sender = current.release().unwrap();
            drop(current);
            pending.settle(&key(), sender, false, None);
            assert!(pending.entries.lock().is_empty());
        }

        #[test]
        fn test_live_open_refuses_a_second_attach() {
            let pending = Arc::new(Pending::default());
            let (first, _, _) = pending.attach("a", b"1").unwrap();
            assert!(matches!(
                pending.attach("a", b"1"),
                Err(Error::BlobAlreadyOpen(partition, name)) if partition == "a" && name == "31"
            ));
            drop(first);
            drop(pending.attach("a", b"1").unwrap());
        }

        #[test]
        fn test_generations_retire_and_release_clean_entries() {
            let pending = Arc::new(Pending::default());
            let (first, _, _) = pending.attach("a", b"1").unwrap();
            let sender = first.release().unwrap();
            drop(first);
            assert_eq!(pending.entries.lock().len(), 1);
            pending.settle(&key(), sender, false, None);
            assert!(pending.entries.lock().is_empty());

            for name in 0..128u64 {
                drop(pending.attach("clean", &name.to_be_bytes()).unwrap());
                assert!(pending.entries.lock().is_empty());
            }
        }
    }

    /// Runs the full suite of tests on the provided storage implementation.
    pub(crate) async fn run_storage_tests<S>(context: impl Spawner, storage: S)
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
        test_concurrent_access(context, &storage).await;
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
    async fn test_concurrent_access<S>(context: impl Spawner, storage: &S)
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
        let write_task = context.child("write").spawn({
            let blob = blob.clone();
            |_| async move {
                blob.write_at(0, IoBuf::from(b"concurrent write"), WriteOptions::default())
                    .await
                    .unwrap();
            }
        });

        let read_task = context.child("read").spawn(move |_| async move {
            blob.read_at(0, 16, ReadOptions::default()).await.unwrap()
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
