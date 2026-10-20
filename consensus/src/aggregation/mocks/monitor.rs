use crate::{IndexSubscription, Monitor as M, types::Epoch};
use commonware_utils::{NZUsize, channel::ring, sync::Mutex};
use std::sync::Arc;

struct Inner {
    epoch: Epoch,
    subscribers: Vec<ring::Sender<Epoch>>,
}

impl Inner {
    const fn new(epoch: Epoch) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use futures::FutureExt;

    #[test]
    fn subscriber_that_falls_behind_sees_newest_epoch() {
        let mut monitor = Monitor::new(Epoch::new(1));
        let (latest, mut subscription) = monitor.subscribe().now_or_never().unwrap();
        assert_eq!(latest, Epoch::new(1));

        // Two updates before the subscriber reads: only the newest is delivered.
        monitor.update(Epoch::new(2));
        monitor.update(Epoch::new(3));
        assert_eq!(
            subscription.recv().now_or_never(),
            Some(Some(Epoch::new(3)))
        );
        assert!(subscription.recv().now_or_never().is_none());
    }
}
