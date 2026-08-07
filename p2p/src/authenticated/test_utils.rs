use commonware_runtime::{Error, IoBufs, Sink};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub(crate) struct BlockingSink<S> {
    inner: S,
    armed: Arc<AtomicBool>,
    blocked: Arc<AtomicBool>,
}

impl<S> BlockingSink<S> {
    pub(crate) const fn new(inner: S, armed: Arc<AtomicBool>, blocked: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            armed,
            blocked,
        }
    }
}

impl<S: Sink> Sink for BlockingSink<S> {
    async fn send(&mut self, bufs: impl Into<IoBufs> + Send) -> Result<(), Error> {
        if self.armed.load(Ordering::SeqCst) {
            self.blocked.store(true, Ordering::SeqCst);
            return futures::future::pending().await;
        }
        self.inner.send(bufs).await
    }
}
