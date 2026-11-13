//! Read gates for cancelling storage operations at a known read.

use super::*;
use std::{collections::VecDeque, future::pending};

/// Parks reads of one partition while armed so tests can cancel their callers.
#[derive(Clone)]
pub struct ReadGate {
    state: Arc<Mutex<ReadGateState>>,
}

impl ReadGate {
    /// Park subsequent reads and reset the number of blocked reads.
    pub fn arm(&self) {
        let mut state = self.state.lock();
        state.armed = true;
        state.blocked = 0;
    }

    /// Let new reads proceed. Previously blocked reads must be cancelled by their caller.
    pub fn disarm(&self) {
        self.state.lock().armed = false;
    }

    /// Number of reads that reached the gate since it was armed.
    pub fn blocked(&self) -> usize {
        self.state.lock().blocked
    }

    /// Return a receiver that resolves when a later read parks at the gate. Each parked read
    /// resolves the oldest receiver still held.
    pub fn parked(&self) -> oneshot::Receiver<()> {
        let (parked, receiver) = oneshot::channel();
        self.state.lock().parked.push_back(parked);
        receiver
    }

    async fn wait(&self, selected: bool) {
        let block = {
            let mut state = self.state.lock();
            if selected && state.armed {
                state.blocked += 1;
                while let Some(parked) = state.parked.pop_front() {
                    if parked.send(()).is_ok() {
                        break;
                    }
                }
                true
            } else {
                false
            }
        };
        if block {
            pending::<()>().await;
        }
    }
}

struct ReadGateState {
    partition: String,
    armed: bool,
    blocked: usize,
    parked: VecDeque<oneshot::Sender<()>>,
}

/// Context wrapper that gates reads of a selected partition.
#[derive(Clone)]
pub struct ReadGateContext<E> {
    inner: E,
    gate: ReadGate,
}

impl<E> ReadGateContext<E> {
    /// Wrap `inner` and return a disarmed gate for reads of `partition`.
    pub fn new(inner: E, partition: String) -> (Self, ReadGate) {
        let gate = ReadGate {
            state: Arc::new(Mutex::new(ReadGateState {
                partition,
                armed: false,
                blocked: 0,
                parked: VecDeque::new(),
            })),
        };
        (
            Self {
                inner,
                gate: gate.clone(),
            },
            gate,
        )
    }
}

forward_context!(ReadGateContext, gate);

impl<E: Spawner> Spawner for ReadGateContext<E> {
    fn shared(mut self, blocking: bool) -> Self {
        self.inner = self.inner.shared(blocking);
        self
    }

    fn dedicated(mut self) -> Self {
        self.inner = self.inner.dedicated();
        self
    }

    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let gate = self.gate;
        self.inner.spawn(move |inner| f(Self { inner, gate }))
    }

    async fn stop(self, value: i32, timeout: Option<std::time::Duration>) -> Result<(), Error> {
        self.inner.stop(value, timeout).await
    }

    fn stopped(&self) -> Signal {
        self.inner.stopped()
    }
}

impl<E: crate::Storage> crate::Storage for ReadGateContext<E> {
    type Blob = ReadGateBlob<E::Blob>;

    async fn open_versioned(
        &self,
        partition: &str,
        name: &[u8],
        versions: std::ops::RangeInclusive<BlobVersion>,
    ) -> Result<(Self::Blob, u64, BlobVersion), Error> {
        let (inner, len, version) = self.inner.open_versioned(partition, name, versions).await?;
        let selected = partition == self.gate.state.lock().partition;
        Ok((
            ReadGateBlob {
                inner,
                gate: self.gate.clone(),
                selected,
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

/// Blob wrapper that parks selected reads before handing them to storage.
pub struct ReadGateBlob<B> {
    inner: B,
    gate: ReadGate,
    selected: bool,
}

impl<B: Blob> Blob for ReadGateBlob<B> {
    async fn read_at_buf(
        &self,
        offset: u64,
        len: usize,
        bufs: impl Into<IoBufsMut> + Send,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        self.gate.wait(self.selected).await;
        self.inner.read_at_buf(offset, len, bufs, options).await
    }

    async fn read_at(
        &self,
        offset: u64,
        len: usize,
        options: ReadOptions,
    ) -> Result<IoBufsMut, Error> {
        self.gate.wait(self.selected).await;
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
