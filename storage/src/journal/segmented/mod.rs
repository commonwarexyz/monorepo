//! Segmented journals with section-based storage.
//!
//! This module provides journal implementations that organize data into sections,
//! where each section is stored in a separate blob.

pub mod fixed;
pub mod glob;
mod manager;
pub mod oversized;
pub mod variable;

/// Test helpers for exercising in-flight sync behavior in segmented journals.
#[cfg(test)]
pub(crate) mod tests {
    use commonware_runtime::{
        telemetry::metrics::{Metric, Registered},
        Blob, BufferPool, BufferPooler, Error as RError, Handle, IoBufs, IoBufsMut, Metrics, Name,
        Storage, Supervisor,
    };
    use commonware_utils::{channel::oneshot, sync::Mutex};
    use std::{mem, sync::Arc};

    pub(crate) type SyncSender = oneshot::Sender<Result<(), RError>>;
    pub(crate) type PendingSyncs = Arc<Mutex<Vec<SyncSender>>>;

    /// Context wrapper whose blobs defer [Blob::start_sync] completion until explicitly released.
    #[derive(Clone)]
    pub(crate) struct DelayedSyncContext<E> {
        pub(crate) inner: E,
        pub(crate) pending: PendingSyncs,
    }

    impl<E: Supervisor> Supervisor for DelayedSyncContext<E> {
        fn name(&self) -> Name {
            self.inner.name()
        }

        fn child(&self, label: &'static str) -> Self {
            Self {
                inner: self.inner.child(label),
                pending: self.pending.clone(),
            }
        }

        fn with_attribute(self, key: &'static str, value: impl std::fmt::Display) -> Self {
            Self {
                inner: self.inner.with_attribute(key, value),
                pending: self.pending,
            }
        }
    }

    impl<E: Metrics> Metrics for DelayedSyncContext<E> {
        fn register<N: Into<String>, H: Into<String>, M: Metric>(
            &self,
            name: N,
            help: H,
            metric: M,
        ) -> Registered<M> {
            self.inner.register(name, help, metric)
        }

        fn encode(&self) -> String {
            self.inner.encode()
        }
    }

    impl<E: BufferPooler> BufferPooler for DelayedSyncContext<E> {
        fn network_buffer_pool(&self) -> &BufferPool {
            self.inner.network_buffer_pool()
        }

        fn storage_buffer_pool(&self) -> &BufferPool {
            self.inner.storage_buffer_pool()
        }
    }

    impl<E: Storage> Storage for DelayedSyncContext<E> {
        type Blob = DelayedSyncBlob<E::Blob>;

        async fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: std::ops::RangeInclusive<u16>,
        ) -> Result<(Self::Blob, u64, u16), RError> {
            let (inner, len, version) =
                self.inner.open_versioned(partition, name, versions).await?;
            Ok((
                DelayedSyncBlob {
                    inner,
                    pending: self.pending.clone(),
                },
                len,
                version,
            ))
        }

        async fn remove(&self, partition: &str, name: Option<&[u8]>) -> Result<(), RError> {
            self.inner.remove(partition, name).await
        }

        async fn scan(&self, partition: &str) -> Result<Vec<Vec<u8>>, RError> {
            self.inner.scan(partition).await
        }
    }

    /// Blob wrapper that parks each started sync until its sender is released.
    #[derive(Clone)]
    pub(crate) struct DelayedSyncBlob<B> {
        inner: B,
        pending: PendingSyncs,
    }

    impl<B: Blob> Blob for DelayedSyncBlob<B> {
        async fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
        ) -> Result<IoBufsMut, RError> {
            self.inner.read_at_buf(offset, len, bufs).await
        }

        async fn read_at(&self, offset: u64, len: usize) -> Result<IoBufsMut, RError> {
            self.inner.read_at(offset, len).await
        }

        async fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), RError> {
            self.inner.write_at(offset, bufs).await
        }

        async fn write_at_sync(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> Result<(), RError> {
            self.inner.write_at_sync(offset, bufs).await
        }

        async fn resize(&self, len: u64) -> Result<(), RError> {
            self.inner.resize(len).await
        }

        async fn sync(&self) -> Result<(), RError> {
            self.inner.sync().await
        }

        async fn start_sync(&self) -> Handle<()> {
            let (sender, receiver) = oneshot::channel();
            self.pending.lock().push(sender);
            let inner = self.inner.clone();
            Handle::from_future(async move {
                receiver.await.map_err(|_| RError::Closed)??;
                inner.sync().await
            })
        }
    }

    /// Complete the oldest `count` pending syncs successfully.
    pub(crate) fn release_next_pending_syncs(pending: &PendingSyncs, count: usize) {
        let senders = {
            let mut pending = pending.lock();
            assert!(
                pending.len() >= count,
                "not enough pending syncs: have {}, need {count}",
                pending.len()
            );
            pending.drain(..count).collect::<Vec<_>>()
        };
        for sender in senders {
            let _ = sender.send(Ok(()));
        }
    }

    /// Complete all pending syncs successfully.
    pub(crate) fn release_pending_syncs(pending: &PendingSyncs) {
        for sender in mem::take(&mut *pending.lock()) {
            let _ = sender.send(Ok(()));
        }
    }

    /// Fail all pending syncs with an injected I/O error.
    pub(crate) fn fail_pending_syncs(pending: &PendingSyncs) {
        for sender in mem::take(&mut *pending.lock()) {
            let err = std::io::Error::other("injected sync failure");
            let _ = sender.send(Err(RError::Io(err.into())));
        }
    }
}
