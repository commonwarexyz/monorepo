use crate::Array;
use bytes::Bytes;
use futures::channel::oneshot;
use std::collections::HashMap;

pub struct Producer<K, V> {
    data: HashMap<K, V>,
}

impl<K, V> Producer<K, V> {
    pub fn new(data: HashMap<K, V>) -> Self {
        Self { data }
    }
}

impl<K: Array, V: Clone> Clone for Producer<K, V> {
    fn clone(&self) -> Self {
        Self {
            data: self.data.clone(),
        }
    }
}

impl<K: Array, V: Into<Bytes> + Clone + Send + 'static> crate::p2p::Producer for Producer<K, V> {
    type Key = K;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (sender, receiver) = oneshot::channel();
        if let Some(value) = self.data.get(&key) {
            let _ = sender.send(value.clone().into());
        }
        receiver
    }
}
