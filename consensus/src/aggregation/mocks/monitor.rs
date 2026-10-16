use crate::{IndexSubscription, Monitor as M, types::Epoch};
use commonware_utils::{NZUsize, channel::ring, sync::Mutex};
use std::sync::Arc;

struct Inner {
    epoch: Epoch,
    subscribers: Vec<ring::Sender<Epoch>>,
}

impl Inner {
    fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            subscribers: Vec::new(),
        }
    }

    fn update(&mut self, epoch: Epoch) {
        self.epoch = epoch;
        self.subscribers
            .retain(|subscriber| subscriber.send_lossy(epoch));
    }

    fn subscribe(&mut self) -> (Epoch, IndexSubscription<Epoch>) {
        let (tx, rx) = ring::channel(NZUsize!(1));
        self.subscribers.push(tx);
        (self.epoch, rx)
    }
}

#[derive(Clone)]
pub struct Monitor {
    inner: Arc<Mutex<Inner>>,
}

impl Monitor {
    pub fn new(epoch: Epoch) -> Self {
        let inner = Inner::new(epoch);
        Self {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    pub fn update(&self, epoch: Epoch) {
        self.inner.lock().update(epoch);
    }
}

impl M for Monitor {
    type Index = Epoch;

    async fn subscribe(&mut self) -> (Self::Index, IndexSubscription<Self::Index>) {
        self.inner.lock().subscribe()
    }
}
