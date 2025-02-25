use crate::Array;
use futures::channel::mpsc;
use futures::SinkExt;

pub enum Event<K, V> {
    Success(K, V),
    Failed(K),
}

pub struct Consumer<K: Array, V> {
    sender: mpsc::Sender<Event<K, V>>,
}

impl<K: Array, V: Clone> Consumer<K, V> {
    pub fn new(sender: mpsc::Sender<Event<K, V>>) -> Self {
        Self { sender }
    }

    pub fn dummy() -> Self {
        let (sender, _) = mpsc::channel(0);
        Self { sender }
    }
}

impl<K: Array, V: Clone + Send + 'static> crate::Consumer for Consumer<K, V> {
    type Key = K;
    type Value = V;
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let _ = self.sender.send(Event::Success(key, value)).await;
        true
    }

    async fn failed(&mut self, key: Self::Key, _failure: ()) {
        let _ = self.sender.send(Event::Failed(key)).await;
    }
}

impl<K: Array, V: Clone> Clone for Consumer<K, V> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}
