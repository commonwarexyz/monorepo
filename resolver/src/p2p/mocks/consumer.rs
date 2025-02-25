use crate::Array;
use futures::channel::mpsc;
use futures::SinkExt;

pub enum Event<K, V, F> {
    Success(K, V),
    Failed(K, F),
}

pub struct Consumer<K: Array, V, F> {
    sender: mpsc::Sender<Event<K, V, F>>,
}

impl<K: Array, V: Clone, F: Clone> Consumer<K, V, F> {
    pub fn new(sender: mpsc::Sender<Event<K, V, F>>) -> Self {
        Self { sender }
    }

    pub fn dummy() -> Self {
        let (sender, _) = mpsc::channel(0);
        Self { sender }
    }
}

impl<K: Array, V: Clone + Send + 'static, F: Clone + Send + 'static> crate::Consumer
    for Consumer<K, V, F>
{
    type Key = K;
    type Value = V;
    type Failure = F;

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) {
        let _ = self.sender.send(Event::Success(key, value)).await;
    }

    async fn failed(&mut self, key: Self::Key, failure: Self::Failure) {
        let _ = self.sender.send(Event::Failed(key, failure)).await;
    }
}

impl<K: Array, V: Clone, F: Clone> Clone for Consumer<K, V, F> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}
