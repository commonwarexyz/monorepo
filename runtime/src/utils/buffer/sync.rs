//! Shared sync observation and durability bookkeeping for buffered blob wrappers.

use crate::{Blob, Error, Handle, IoBufs, IoBufsMut};
use commonware_utils::sync::{AsyncRwLock, AsyncRwLockWriteGuard};
use futures::{
    future::{BoxFuture, Shared as FuturesShared},
    FutureExt as _,
};
use std::{future::Future, sync::Arc};

/// A cloneable observer for an issued sync.
type Shared = FuturesShared<BoxFuture<'static, Result<(), Error>>>;

/// Converts a sync future into a shared completion.
fn share(fut: impl Future<Output = Result<(), Error>> + Send + 'static) -> Shared {
    fut.boxed().shared()
}

/// Returns a handle that observes a shared sync completion.
fn observe(sync: Shared) -> Handle<()> {
    Handle::from_future(sync)
}

/// A blob wrapper that gates mutations behind any outstanding [`Blob::start_sync`].
///
/// Reads pass through immediately. Writes, resizes, and sync operations first wait for the last
/// started sync to complete, so writes issued after `start_sync` are not covered by or reordered
/// before that sync.
#[derive(Clone)]
pub(crate) struct Gated<B: Blob> {
    inner: B,
    state: Arc<AsyncRwLock<State>>,
}

impl<B: Blob> Gated<B> {
    pub(crate) fn new(inner: B, dirty: bool) -> Self {
        Self {
            inner,
            state: Arc::new(AsyncRwLock::new(if dirty {
                State::Dirty
            } else {
                State::Clean
            })),
        }
    }

    pub(crate) fn inner(&self) -> B {
        self.inner.clone()
    }

    async fn mutation_state(&self) -> Result<AsyncRwLockWriteGuard<'_, State>, Error> {
        let mut state = self.state.write().await;
        if let State::InFlight(syncing) = &*state {
            syncing.clone().await?;
            *state = State::Clean;
        }
        Ok(state)
    }
}

impl<B: Blob> Blob for Gated<B> {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
    ) -> Result<IoBufsMut, Error> {
        self.inner.read_at_buf(offset, len, bufs).await
    }

    async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, Error> {
        self.inner.read_at(offset, len).await
    }

    async fn write_at(&self, offset: u64, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        let mut state = self.mutation_state().await?;
        state.write_at(&self.inner, offset, bufs).await
    }

    async fn write_at_sync(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        let mut state = self.mutation_state().await?;
        state.write_at_sync(&self.inner, offset, bufs).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        let mut state = self.mutation_state().await?;
        state.resize(&self.inner, len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.state.write().await.sync(&self.inner).await?;
        Ok(())
    }

    async fn start_sync(&self) -> Handle<()> {
        self.state
            .write()
            .await
            .start(&self.inner)
            .await
            .map(observe)
            .unwrap_or_else(|| Handle::ready(Ok(())))
    }
}

/// Durability state for mutations already issued to the underlying blob.
///
/// Bytes still held only in a write buffer are not represented here. Once those bytes are flushed
/// to the blob, callers update this state through the methods below.
enum State {
    /// No issued mutation requires a sync.
    Clean,

    /// At least one issued plain write or resize requires a full blob sync.
    Dirty,

    /// A full blob sync has been issued and can be observed by multiple callers.
    InFlight(Shared),
}

impl State {
    /// Returns whether a full sync still needs to be issued.
    const fn is_dirty(&self) -> bool {
        matches!(self, Self::Dirty)
    }

    /// Records that an issued mutation must be covered by a future full sync.
    fn mark_dirty(&mut self) {
        *self = Self::Dirty;
    }

    /// Writes bytes to `blob` and records that they need a future full sync.
    async fn write_at<B: Blob>(
        &mut self,
        blob: &B,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        blob.write_at(offset, bufs).await?;
        self.mark_dirty();
        Ok(())
    }

    /// Writes bytes to `blob` and makes them durable.
    ///
    /// Uses [`Blob::write_at_sync`] when no earlier mutation requires a new full sync. Otherwise,
    /// writes the bytes and then syncs the blob.
    ///
    /// [`Gated`] only calls this after [`Gated::mutation_state`] has drained any in-flight sync
    /// under the held write guard, so the state here is only ever `Clean` or `Dirty`.
    async fn write_at_sync<B: Blob>(
        &mut self,
        blob: &B,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
    ) -> Result<(), Error> {
        if self.is_dirty() {
            self.write_at(blob, offset, bufs).await?;
            self.sync(blob).await
        } else {
            // Mark dirty before the write so that, if `write_at_sync` fails, a later sync does not
            // treat the drained buffer as durable.
            *self = Self::Dirty;
            blob.write_at_sync(offset, bufs).await?;
            *self = Self::Clean;
            Ok(())
        }
    }

    /// Resizes `blob` and records that the resize needs a future full sync.
    async fn resize<B: Blob>(&mut self, blob: &B, len: u64) -> Result<(), Error> {
        blob.resize(len).await?;
        self.mark_dirty();
        Ok(())
    }

    /// Ensures mutations represented by this state are durable.
    async fn sync<B: Blob>(&mut self, blob: &B) -> Result<(), Error> {
        match self {
            Self::Clean => Ok(()),
            Self::Dirty => {
                blob.sync().await?;
                *self = Self::Clean;
                Ok(())
            }
            Self::InFlight(syncing) => {
                syncing.clone().await?;
                *self = Self::Clean;
                Ok(())
            }
        }
    }

    /// Starts a full blob sync or returns the in-flight sync that already covers this state.
    ///
    /// Returns `None` when no issued mutation requires a sync.
    async fn start<B: Blob>(&mut self, blob: &B) -> Option<Shared> {
        match self {
            Self::Clean => None,
            Self::Dirty => {
                let syncing = share(blob.start_sync().await);
                *self = Self::InFlight(syncing.clone());
                Some(syncing)
            }
            Self::InFlight(syncing) => Some(syncing.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Gated;
    use crate::{
        buffer::tests::ControlledSyncBlob, deterministic, Blob as _, Error, Runner as _,
        Spawner as _, Supervisor as _,
    };
    use commonware_macros::test_traced;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    fn new_gated(dirty: bool) -> (ControlledSyncBlob, Gated<ControlledSyncBlob>) {
        let blob = ControlledSyncBlob::new();
        let gated = Gated::new(blob.clone(), dirty);
        (blob, gated)
    }

    #[test_traced]
    fn test_gated_clean_start_sync_and_sync_are_noops() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, gated) = new_gated(false);

            // With no issued mutation, start_sync resolves immediately and issues nothing.
            gated.start_sync().await.await.unwrap();
            assert_eq!(blob.pending_syncs(), 0);
            assert_eq!(blob.syncs(), 0);

            // sync on a clean blob is also a no-op.
            gated.sync().await.unwrap();
            assert_eq!(blob.syncs(), 0);
        });
    }

    #[test_traced]
    fn test_gated_write_then_sync_issues_full_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, gated) = new_gated(false);

            gated.write_at(0, b"ab").await.unwrap();
            assert_eq!(blob.writes(), 1);

            gated.sync().await.unwrap();
            assert_eq!(blob.syncs(), 1);

            // The blob is clean again, so a second sync does nothing.
            gated.sync().await.unwrap();
            assert_eq!(blob.syncs(), 1);
        });
    }

    #[test_traced]
    fn test_gated_write_at_sync_uses_fast_path_when_clean() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, gated) = new_gated(false);

            // A clean blob uses the durable single-write fast path (no separate full sync).
            gated.write_at_sync(0, b"ab").await.unwrap();
            assert_eq!(blob.writes(), 1);
            assert_eq!(blob.syncs(), 0);

            // The state is clean afterward, so a follow-up sync is a no-op.
            gated.sync().await.unwrap();
            assert_eq!(blob.syncs(), 0);
        });
    }

    #[test_traced]
    fn test_gated_write_at_sync_falls_back_to_full_sync_when_dirty() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, gated) = new_gated(false);

            // An earlier plain write makes the blob dirty, so write_at_sync must write and then
            // issue a full sync to cover the earlier mutation.
            gated.write_at(0, b"a").await.unwrap();
            gated.write_at_sync(1, b"b").await.unwrap();
            assert_eq!(blob.writes(), 2);
            assert_eq!(blob.syncs(), 1);
        });
    }

    #[test_traced]
    fn test_gated_start_sync_gates_later_write() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, gated) = new_gated(false);

            gated.write_at(0, b"a").await.unwrap();
            let handle = gated.start_sync().await;
            assert_eq!(blob.pending_syncs(), 1);

            let done = Arc::new(AtomicUsize::new(0));
            let done_clone = done.clone();
            let gated_clone = gated.clone();
            let waiter = context.child("writer").spawn(|_| async move {
                gated_clone.write_at(1, b"b".to_vec()).await.unwrap();
                done_clone.fetch_add(1, Ordering::Relaxed);
            });

            crate::utils::reschedule().await;
            assert_eq!(done.load(Ordering::Relaxed), 0);
            assert_eq!(
                blob.writes(),
                1,
                "a write issued after start_sync must wait for the in-flight sync"
            );

            blob.release_next_sync();
            handle.await.unwrap();
            while done.load(Ordering::Relaxed) != 1 {
                crate::utils::reschedule().await;
            }
            waiter.await.unwrap();
            assert_eq!(blob.writes(), 2);
            assert_eq!(blob.pending_syncs(), 0);
        });
    }

    #[test_traced]
    fn test_gated_concurrent_start_sync_shares_one_underlying_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, gated) = new_gated(false);

            gated.write_at(0, b"a").await.unwrap();
            let first = gated.start_sync().await;
            // A second start_sync with no intervening write reuses the in-flight sync rather than
            // issuing a new one.
            let second = gated.start_sync().await;
            assert_eq!(blob.pending_syncs(), 1);

            blob.release_next_sync();
            first.await.unwrap();
            second.await.unwrap();
            assert_eq!(blob.pending_syncs(), 0);
        });
    }

    #[test_traced]
    fn test_gated_sync_observes_in_flight_without_reissuing() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let (blob, gated) = new_gated(false);

            gated.write_at(0, b"a").await.unwrap();
            let handle = gated.start_sync().await;
            assert_eq!(blob.pending_syncs(), 1);

            let done = Arc::new(AtomicUsize::new(0));
            let done_clone = done.clone();
            let gated_clone = gated.clone();
            let waiter = context.child("sync").spawn(|_| async move {
                gated_clone.sync().await.unwrap();
                done_clone.fetch_add(1, Ordering::Relaxed);
            });

            crate::utils::reschedule().await;
            assert_eq!(done.load(Ordering::Relaxed), 0);
            assert_eq!(blob.pending_syncs(), 1);

            blob.release_next_sync();
            handle.await.unwrap();
            while done.load(Ordering::Relaxed) != 1 {
                crate::utils::reschedule().await;
            }
            waiter.await.unwrap();
            // sync observed the in-flight start_sync rather than issuing its own blob sync.
            assert_eq!(blob.syncs(), 0);
            assert_eq!(blob.pending_syncs(), 0);
        });
    }

    #[test_traced]
    fn test_gated_in_flight_error_propagates() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, gated) = new_gated(false);

            gated.write_at(0, b"a").await.unwrap();
            let first = gated.start_sync().await;
            let second = gated.start_sync().await;
            assert_eq!(blob.pending_syncs(), 1);

            // Failing the in-flight sync surfaces the error to every observer, including a later
            // mutation and a later sync (the failed state is conservatively retained).
            blob.fail_next_sync();
            assert!(matches!(first.await, Err(Error::Closed)));
            assert!(matches!(second.await, Err(Error::Closed)));
            assert!(matches!(gated.write_at(1, b"b").await, Err(Error::Closed)));
            assert!(matches!(gated.sync().await, Err(Error::Closed)));
        });
    }

    #[test_traced]
    fn test_gated_resize_marks_dirty() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (blob, gated) = new_gated(false);

            gated.resize(8).await.unwrap();
            gated.sync().await.unwrap();
            assert_eq!(blob.syncs(), 1);
        });
    }
}
