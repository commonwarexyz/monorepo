use futures::channel::mpsc;

use crate::ordered_broadcast::Epoch;
use crate::Monitor as M;

#[derive(Clone)]
pub struct Monitor {
    epoch: Epoch,
    subscribers: Vec<mpsc::Sender<Epoch>>,
}

impl Monitor {
    pub fn new(epoch: Epoch) -> Self {
        Self {
            epoch,
            subscribers: Vec::new(),
        }
    }
}

impl M for Monitor {
    type Index = Epoch;

    fn latest(&self) -> Self::Index {
        self.epoch
    }

    fn subscribe(&mut self) -> mpsc::Receiver<Self::Index> {
        let (tx, rx) = mpsc::channel(1);
        self.subscribers.push(tx);
        rx
    }
}
