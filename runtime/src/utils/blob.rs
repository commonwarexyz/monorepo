use crate::{Blob, Error, Handle, IoBufs};
use futures::{
    future::{BoxFuture, Shared},
    FutureExt as _,
};

/// A shareable observer for an in-flight sync: one fsync, many waiters share the cloned result.
pub type SyncObserver = Shared<BoxFuture<'static, Result<(), Error>>>;

/// Tracks a single-owner blob's durability so each mutation first waits for any outstanding
/// asynchronous sync to finish (the durability gate).
///
/// The owner drives every mutation through `&mut self`, so the gate needs no interior locking.
/// Reads never consult the gate, so read-only handles hold the bare blob rather than a gated
/// wrapper.
pub(crate) struct SyncGate {
    state: State,
}

enum State {
    /// The blob is durable: no buffered mutations and no in-flight sync.
    Clean,
    /// The blob holds mutations that are not yet durable.
    Dirty,
    /// A sync is in flight; the next mutation must wait for it.
    Syncing(SyncObserver),
}

impl SyncGate {
    /// Create a gate for a blob that is already durable (`initially_dirty == false`) or already
    /// holds unsynced mutations (`initially_dirty == true`).
    pub(crate) const fn new(initially_dirty: bool) -> Self {
        Self {
            state: if initially_dirty {
                State::Dirty
            } else {
                State::Clean
            },
        }
    }

    /// Wait for any in-flight sync to finish, returning whether one was drained.
    async fn drain(&mut self) -> Result<bool, Error> {
        let State::Syncing(handle) = &mut self.state else {
            return Ok(false);
        };

        let result = handle.clone().await;
        self.state = if result.is_ok() {
            State::Clean
        } else {
            State::Dirty
        };
        result.map(|_| true)
    }

    /// Write to `blob` after draining any in-flight sync, leaving the blob dirty.
    pub(crate) async fn write_at<B: Blob>(
        &mut self,
        blob: &B,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.drain().await?;
        blob.write_at(offset, bufs).await?;
        self.state = State::Dirty;
        Ok(())
    }

    /// Write to `blob` and make it durable, draining any in-flight sync first.
    ///
    /// Uses [`Blob::write_at_sync`] when there are no earlier unsynced mutations. Otherwise, writes
    /// the bytes and then syncs the blob.
    pub(crate) async fn write_at_sync<B: Blob>(
        &mut self,
        blob: &B,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        self.drain().await?;
        if matches!(self.state, State::Dirty) {
            blob.write_at(offset, bufs).await?;
            blob.sync().await?;
        } else {
            self.state = State::Dirty;
            blob.write_at_sync(offset, bufs).await?;
        }
        self.state = State::Clean;
        Ok(())
    }

    /// Resize `blob` after draining any in-flight sync, leaving the blob dirty.
    pub(crate) async fn resize<B: Blob>(&mut self, blob: &B, len: u64) -> Result<(), Error> {
        self.drain().await?;
        blob.resize(len).await?;
        self.state = State::Dirty;
        Ok(())
    }

    /// Make `blob` durable, waiting for any in-flight sync first and skipping the fsync if the blob
    /// is already clean.
    pub(crate) async fn sync<B: Blob>(&mut self, blob: &B) -> Result<(), Error> {
        if self.drain().await? || matches!(self.state, State::Clean) {
            return Ok(());
        }
        blob.sync().await?;
        self.state = State::Clean;
        Ok(())
    }

    /// Begin making `blob` durable. Awaiting the returned [`Handle`] waits for the same guarantee as
    /// [`Self::sync`]. The next mutation drains the started sync.
    pub(crate) async fn start_sync<B: Blob>(&mut self, blob: &B) -> Handle<()> {
        if let Err(err) = self.drain().await {
            return Handle::ready(Err(err));
        }
        if matches!(self.state, State::Clean) {
            return Handle::ready(Ok(()));
        }

        let handle = blob.start_sync().await.boxed().shared();
        self.state = State::Syncing(handle.clone());

        Handle::from_future(handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, reschedule, IoBufsMut, Runner as _, Spawner as _, Supervisor as _};
    use commonware_macros::test_traced;
    use commonware_utils::sync::Notify;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    #[derive(Clone)]
    struct ControlledBlob {
        released: Arc<AtomicBool>,
        release: Arc<Notify>,
        writes: Arc<AtomicUsize>,
        syncs: Arc<AtomicUsize>,
        starts: Arc<AtomicUsize>,
        start_waits: Arc<AtomicUsize>,
        start_completions: Arc<AtomicUsize>,
        fail_start: Arc<AtomicBool>,
    }

    impl ControlledBlob {
        fn new() -> Self {
            Self {
                released: Arc::new(AtomicBool::new(false)),
                release: Arc::new(Notify::new()),
                writes: Arc::new(AtomicUsize::new(0)),
                syncs: Arc::new(AtomicUsize::new(0)),
                starts: Arc::new(AtomicUsize::new(0)),
                start_waits: Arc::new(AtomicUsize::new(0)),
                start_completions: Arc::new(AtomicUsize::new(0)),
                fail_start: Arc::new(AtomicBool::new(false)),
            }
        }

        fn writes(&self) -> usize {
            self.writes.load(Ordering::SeqCst)
        }

        fn syncs(&self) -> usize {
            self.syncs.load(Ordering::SeqCst)
        }

        fn starts(&self) -> usize {
            self.starts.load(Ordering::SeqCst)
        }

        fn start_waits(&self) -> usize {
            self.start_waits.load(Ordering::SeqCst)
        }

        fn start_completions(&self) -> usize {
            self.start_completions.load(Ordering::SeqCst)
        }

        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            self.release.notify_waiters();
        }

        fn fail_start_sync(&self) {
            self.fail_start.store(true, Ordering::SeqCst);
        }

        async fn wait_released(&self) {
            while !self.released.load(Ordering::SeqCst) {
                self.release.notified().await;
            }
        }
    }

    impl Blob for ControlledBlob {
        async fn read_at(&self, _offset: u64, _len: usize) -> Result<IoBufsMut, Error> {
            Err(Error::BlobInsufficientLength)
        }

        async fn read_at_buf(
            &self,
            _offset: u64,
            _len: usize,
            _bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, Error> {
            Err(Error::BlobInsufficientLength)
        }

        async fn write_at(
            &self,
            _offset: u64,
            _bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), Error> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        async fn write_at_sync(
            &self,
            _offset: u64,
            _bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), Error> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            self.sync().await
        }

        async fn resize(&self, _len: u64) -> Result<(), Error> {
            Ok(())
        }

        async fn sync(&self) -> Result<(), Error> {
            self.syncs.fetch_add(1, Ordering::SeqCst);
            self.wait_released().await;
            Ok(())
        }

        async fn start_sync(&self) -> Handle<()> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            let this = self.clone();
            Handle::from_future(async move {
                this.start_waits.fetch_add(1, Ordering::SeqCst);
                this.wait_released().await;
                this.start_completions.fetch_add(1, Ordering::SeqCst);
                if this.fail_start.load(Ordering::SeqCst) {
                    Err(Error::Io(
                        std::io::Error::other("injected sync failure").into(),
                    ))
                } else {
                    Ok(())
                }
            })
        }
    }

    #[test_traced("DEBUG")]
    fn test_write_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = ControlledBlob::new();
            let mut gate = SyncGate::new(false);

            gate.write_at(&blob, 0, vec![b'a']).await.unwrap();
            let handle = gate.start_sync(&blob).await;
            assert_eq!(blob.starts(), 1);

            let writer_blob = blob.clone();
            let write = context.child("write").spawn(|_| async move {
                gate.write_at(&writer_blob, 1, vec![b'b']).await.unwrap();
                gate
            });

            while blob.start_waits() == 0 {
                reschedule().await;
            }

            assert_eq!(blob.start_waits(), 1);
            assert_eq!(blob.syncs(), 0);
            assert_eq!(blob.writes(), 1);

            blob.release();
            let _gate = write.await.unwrap();
            handle.await.unwrap();

            assert_eq!(blob.writes(), 2);
            assert_eq!(blob.syncs(), 0);
            assert_eq!(blob.start_completions(), 1);
        });
    }

    #[test_traced("DEBUG")]
    fn test_sync_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = ControlledBlob::new();
            let mut gate = SyncGate::new(true);

            let handle = gate.start_sync(&blob).await;
            assert_eq!(blob.starts(), 1);

            let waiter_blob = blob.clone();
            let sync = context.child("sync").spawn(|_| async move {
                gate.sync(&waiter_blob).await.unwrap();
                gate
            });

            while blob.start_waits() == 0 {
                reschedule().await;
            }

            assert_eq!(blob.starts(), 1);
            assert_eq!(blob.syncs(), 0);

            blob.release();
            let _gate = sync.await.unwrap();
            handle.await.unwrap();

            assert_eq!(blob.start_completions(), 1);
            assert_eq!(blob.syncs(), 0);
        });
    }

    #[test_traced("DEBUG")]
    fn test_start_sync_handle_reports_drained_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = ControlledBlob::new();
            blob.fail_start_sync();
            let mut gate = SyncGate::new(true);

            let handle = gate.start_sync(&blob).await;
            assert_eq!(blob.starts(), 1);

            let waiter_blob = blob.clone();
            let sync = context
                .child("sync")
                .spawn(|_| async move { gate.sync(&waiter_blob).await });

            while blob.start_waits() == 0 {
                reschedule().await;
            }

            blob.release();

            let sync_result = sync.await.unwrap();
            assert!(matches!(sync_result, Err(Error::Io(_))));
            assert!(matches!(handle.await, Err(Error::Io(_))));
            assert_eq!(blob.start_completions(), 1);
        });
    }

    #[test_traced("DEBUG")]
    fn test_start_sync_waits_for_in_flight_start_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context: deterministic::Context| async move {
            let blob = ControlledBlob::new();
            let mut gate = SyncGate::new(true);

            let first = gate.start_sync(&blob).await;
            assert_eq!(blob.starts(), 1);

            let next_blob = blob.clone();
            let second = context.child("second").spawn(|_| async move {
                let handle = gate.start_sync(&next_blob).await;
                handle.await
            });

            while blob.start_waits() == 0 {
                reschedule().await;
            }

            assert_eq!(blob.start_waits(), 1);
            assert_eq!(blob.starts(), 1);

            blob.release();
            second.await.unwrap().unwrap();

            assert_eq!(blob.starts(), 1);
            first.await.unwrap();
            assert_eq!(blob.start_completions(), 1);
        });
    }
}
