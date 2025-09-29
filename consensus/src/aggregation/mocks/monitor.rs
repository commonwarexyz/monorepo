use crate::{types::Epoch, Monitor as M};
use futures::channel::mpsc;
use std::sync::{Arc, Mutex};

struct Inner {
    epoch: Epoch,
    subscribers: Vec<mpsc::Sender<Epoch>>,
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
        for subscriber in &mut self.subscribers {
            subscriber.try_send(epoch).ok();
        }
    }

    fn subscribe(&mut self) -> (Epoch, mpsc::Receiver<Epoch>) {
        let (tx, rx) = mpsc::channel(1);
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
        self.inner.lock().unwrap().update(epoch);
    }
}

impl M for Monitor {
    type Index = Epoch;

    async fn subscribe(&mut self) -> (Self::Index, mpsc::Receiver<Self::Index>) {
        self.inner.lock().unwrap().subscribe()
    }
}
