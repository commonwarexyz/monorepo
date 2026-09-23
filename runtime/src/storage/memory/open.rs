//! Logical opens for the memory backend and its deterministic fault stack.

use crate::{BlobVersion, Error, Handle, IoBufs, IoBufsMut, ReadOptions, WriteOptions};
use commonware_formatting::hex;
use commonware_utils::sync::{Mutex, MutexGuard};
use futures::{Future, FutureExt as _};
use std::{
    collections::BTreeMap,
    ptr,
    sync::{Arc, Weak},
};

/// Identifies a blob by its partition and name.
type Key = (String, Vec<u8>);

/// Couples namespace transactions to logical user-handle lifetimes.
///
/// Only the synchronous memory backend and its deterministic wrappers use this owner.
/// Their namespace futures must complete in one poll while the registry is locked.
/// The registry lock also covers synchronous raw-image replacement and last-owner cleanup.
#[derive(Default)]
pub(crate) struct Opens {
    live: Mutex<BTreeMap<Key, Weak<Live>>>,
    #[cfg(test)]
    test: tests::TestState,
}

impl Opens {
    /// Registers an exclusive open atomically with opening the underlying blob.
    ///
    /// The open future must complete in one poll. The returned guard retains the
    /// namespace lock until [`Opened::finish`] returns the blob.
    pub(crate) fn open<B: crate::Blob>(
        self: &Arc<Self>,
        partition: &str,
        name: &[u8],
        open: impl Future<Output = Result<(B, u64, BlobVersion), Error>> + Send,
    ) -> Result<Opened<'_, B>, Error> {
        #[cfg(test)]
        self.test.registry_entry(self.live.is_locked());
        let mut opens = self.live.lock();
        let (inner, len, version) = open
            .now_or_never()
            .expect("memory namespace work completes in one poll")?;
        #[cfg(test)]
        self.test.namespace_handoff();
        let key = (partition.to_owned(), name.to_vec());

        // Observing liveness must not acquire an owner whose destructor locks this registry.
        let live = opens
            .get(&key)
            .is_some_and(|identity| identity.strong_count() != 0);
        #[cfg(test)]
        self.test.observe_open(opens.get(&key));
        if live {
            return Err(Error::BlobAlreadyOpen(partition.to_owned(), hex(name)));
        }
        let live = Arc::new(Live {
            key: key.clone(),
            opens: self.clone(),
        });
        opens.insert(key, Arc::downgrade(&live));
        Ok(Opened {
            _namespace: opens,
            result: (Blob { inner, _live: live }, len, version),
        })
    }

    /// Retires registrations atomically with a blob or partition removal.
    ///
    /// The removal future must complete in one poll. Failed removals leave registrations intact.
    pub(crate) fn remove<R>(
        &self,
        partition: &str,
        name: Option<&[u8]>,
        remove: impl Future<Output = Result<R, Error>> + Send,
    ) -> Result<R, Error> {
        self.replace(partition, name, || {
            let removed = remove
                .now_or_never()
                .expect("memory namespace work completes in one poll")?;
            #[cfg(test)]
            self.test.namespace_handoff();
            Ok(removed)
        })
    }

    /// Retires registrations atomically with removal or installation of a raw memory image.
    pub(crate) fn replace<R>(
        &self,
        partition: &str,
        name: Option<&[u8]>,
        replace: impl FnOnce() -> Result<R, Error>,
    ) -> Result<R, Error> {
        #[cfg(test)]
        self.test.registry_entry(self.live.is_locked());
        let mut opens = self.live.lock();
        let replaced = replace()?;
        opens.retain(|(stored_partition, stored_name), _| {
            stored_partition != partition || name.is_some_and(|name| stored_name != name)
        });
        Ok(replaced)
    }
}

/// Keeps admission in the namespace transaction until predecessor crash evidence is retired.
pub(crate) struct Opened<'a, B> {
    // Release the registry before dropping the user lease, including during unwinding.
    _namespace: MutexGuard<'a, BTreeMap<Key, Weak<Live>>>,
    result: (Blob<B>, u64, BlobVersion),
}

impl<B> Opened<'_, B> {
    pub(crate) fn finish(self) -> (Blob<B>, u64, BlobVersion) {
        self.result
    }
}

/// Marks a blob as open until its last handle clone drops or the blob is removed.
struct Live {
    key: Key,
    opens: Arc<Opens>,
}

impl Drop for Live {
    fn drop(&mut self) {
        let mut opens = self.opens.live.lock();
        if opens
            .get(&self.key)
            .is_some_and(|live| ptr::eq(live.as_ptr(), self))
        {
            opens.remove(&self.key);
        }
    }
}

/// A blob handle whose open stays exclusive until every clone drops or the blob is removed.
#[derive(Clone)]
pub struct Blob<B> {
    inner: B,
    _live: Arc<Live>,
}

impl<B: crate::Blob> crate::Blob for Blob<B> {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        self.inner.read_at_buf(offset, len, bufs, options).await
    }

    async fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        self.inner.read_at(offset, len, options).await
    }

    async fn write_at(
        &self,
        offset: u64,
        bufs: impl Into<IoBufs> + Send,
        options: WriteOptions,
    ) -> Result<(), Error> {
        self.inner.write_at(offset, bufs, options).await
    }

    async fn resize(&self, len: u64) -> Result<(), Error> {
        self.inner.resize(len).await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.inner.sync().await
    }

    async fn start_sync(&self) -> Handle<()> {
        self.inner.start_sync().await
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        Blob as _, BufferPooler as _, Runner as _, Storage as _, deterministic::Runner,
        mocks::MemoryStorage,
    };
    use std::{
        env,
        sync::mpsc::{self, Receiver, Sender},
        thread,
        time::{Duration, Instant},
    };

    type OpenObservation = (Sender<usize>, Receiver<()>);

    /// One-shot observations and pauses for a single logical-open registry.
    #[derive(Default)]
    pub(super) struct TestState {
        open_observation: Mutex<Option<OpenObservation>>,
        namespace_handoff: Mutex<Option<(Sender<()>, Receiver<()>)>>,
        registry_observation: Mutex<Option<Sender<bool>>>,
    }

    impl Opens {
        /// Pause the next namespace handoff after reporting arrival through `entered`.
        /// Resume when `released` receives a message or its sender drops.
        pub(crate) fn pause_namespace(&self, entered: Sender<()>, released: Receiver<()>) {
            *self.test.namespace_handoff.lock() = Some((entered, released));
        }

        /// Report the lock state when the next namespace operation attempts entry.
        pub(crate) fn watch_registry(&self, entered: Sender<bool>) {
            *self.test.registry_observation.lock() = Some(entered);
        }
    }

    impl TestState {
        /// Report the namespace handoff and wait for release.
        pub(super) fn namespace_handoff(&self) {
            let hook = self.namespace_handoff.lock().take();
            if let Some((entered, released)) = hook {
                entered.send(()).unwrap();
                let _ = released.recv();
            }
        }

        /// Report the lock state before attempting registry entry.
        pub(super) fn registry_entry(&self, locked: bool) {
            if let Some(entered) = self.registry_observation.lock().take() {
                entered.send(locked).unwrap();
            }
        }

        /// Report the current owner count and wait for release. A missing registration has zero owners.
        pub(super) fn observe_open(&self, identity: Option<&Weak<Live>>) {
            let hook = self.open_observation.lock().take();
            if let Some((entered, released)) = hook {
                entered
                    .send(identity.map_or(0, Weak::strong_count))
                    .unwrap();
                let _ = released.recv();
            }
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn test_open_racing_last_blob_drop() {
        const CHILD: &str = "COMMONWARE_TEST_OPEN_LAST_DROP";
        if env::var_os(CHILD).is_none() {
            crate::storage::tests::shared::run_child(CHILD, "1");
            return;
        }

        Runner::default().start(|context| async move {
            let context = MemoryStorage::new(context.storage_buffer_pool().clone());
            let (blob, _) = context.open("partition", b"blob").await.unwrap();
            blob.write_at(0, b"saved", WriteOptions::default())
                .await
                .unwrap();
            blob.sync().await.unwrap();
            let identity = Arc::downgrade(&blob._live);
            let opens = blob._live.opens.clone();
            let (release_drop, dropping) = mpsc::channel();
            let dropper = thread::spawn(move || {
                dropping.recv().unwrap();
                drop(blob);
            });
            let (entered, entering) = mpsc::channel();
            let (release, released) = mpsc::channel();
            *opens.test.open_observation.lock() = Some((entered, released));
            let coordinator = thread::spawn(move || {
                let timeout = Duration::from_secs(5);
                let owners = entering.recv_timeout(timeout).unwrap();
                release_drop.send(()).unwrap();

                // The strong count changes when the external owner drops. Successful opens below
                // verify that the registry progresses while the drop is scheduled.
                let deadline = Instant::now() + timeout;
                while identity.strong_count() == owners {
                    assert!(Instant::now() < deadline, "external owner did not drop");
                    thread::yield_now();
                }
                release.send(()).unwrap();
            });
            assert!(matches!(
                context.open("partition", b"blob").await,
                Err(Error::BlobAlreadyOpen(partition, name))
                    if partition == "partition" && name == "626c6f62"
            ));
            coordinator.join().unwrap();
            dropper.join().unwrap();
            drop(context.open("partition", b"independent").await.unwrap());
            let (blob, size) = context.open("partition", b"blob").await.unwrap();
            assert_eq!(size, 5);
            assert_eq!(
                blob.read_at(0, 5, ReadOptions::default())
                    .await
                    .unwrap()
                    .coalesce(),
                b"saved",
            );
        });
    }
}
